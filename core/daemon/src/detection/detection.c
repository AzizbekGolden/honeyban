// SPDX-License-Identifier: MIT

#include "detection.h"

#include "../jails/jails.h"
#include "../jails/ipkey.h"
#include "../log.h"
#include "../timeutil.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#define DET_TABLE_CAP 32768u
#define DET_EVICT_SCAN 64u
#define DET_MAX_SCORE 100000

#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_SYN 0x02

typedef struct {
    int used;
    hb_det_key key;
    int64_t score;
    uint64_t last_seen;
    uint64_t last_forward;
    uint32_t syn_hits;
    uint32_t portscan_hits;
    uint32_t ssh_hits;
    uint32_t journal_hits;
} hb_det_entry;

typedef struct {
    hb_det_entry *table;
    uint32_t cap;
    uint32_t evict_cursor;

    uint32_t min_confidence;
    uint32_t high_confidence_bypass;
    int32_t score_threshold;
    int32_t decay_per_sec;
    int32_t syn_score;
    int32_t portscan_score;
    int32_t ssh_score;
    int32_t journal_score;
    uint32_t forward_cooldown_sec;
} hb_detection_state;

typedef struct {
    hb_det_key key;
    uint32_t confidence;
    int32_t signal_score;
    int kind; // 1 syn, 2 portscan, 3 ssh, 4 journal
} hb_det_signal;

static uint32_t clamp_u32(uint32_t v, uint32_t minv, uint32_t maxv) {
    if (v < minv) return minv;
    if (v > maxv) return maxv;
    return v;
}

static int32_t clamp_i32(int32_t v, int32_t minv, int32_t maxv) {
    if (v < minv) return minv;
    if (v > maxv) return maxv;
    return v;
}

static uint32_t env_u32(const char *k, uint32_t defv, uint32_t minv, uint32_t maxv) {
    const char *s = getenv(k);
    if (!s || !*s) return defv;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0') return defv;
    return clamp_u32((uint32_t)v, minv, maxv);
}

static int32_t env_i32(const char *k, int32_t defv, int32_t minv, int32_t maxv) {
    const char *s = getenv(k);
    if (!s || !*s) return defv;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0') return defv;
    return clamp_i32((int32_t)v, minv, maxv);
}

static void detection_load_cfg(hb_detection_state *st) {
    if (!st) return;
    st->min_confidence = env_u32("HONEYBAN_DET_MIN_CONFIDENCE", 55, 1, 100);
    st->high_confidence_bypass = env_u32("HONEYBAN_DET_HIGH_CONF_BYPASS", 90, 1, 100);
    st->score_threshold = env_i32("HONEYBAN_DET_SCORE_THRESHOLD", 80, 1, 10000);
    st->decay_per_sec = env_i32("HONEYBAN_DET_DECAY_PER_SEC", 2, 0, 1000);
    st->syn_score = env_i32("HONEYBAN_DET_SYN_SCORE", 8, 1, 1000);
    st->portscan_score = env_i32("HONEYBAN_DET_PORTSCAN_SCORE", 20, 1, 1000);
    st->ssh_score = env_i32("HONEYBAN_DET_SSH_SCORE", 30, 1, 1000);
    st->journal_score = env_i32("HONEYBAN_DET_JOURNAL_SCORE", 35, 1, 1000);
    st->forward_cooldown_sec = env_u32("HONEYBAN_DET_FORWARD_COOLDOWN_SEC", 1, 0, 600);
}

static hb_det_entry *det_find_entry(hb_detection_state *st, const hb_det_key *key) {
    if (!st || !st->table || !key) return NULL;
    uint32_t idx = hb_det_key_hash(key) & (st->cap - 1);
    for (uint32_t i = 0; i < st->cap; i++) {
        hb_det_entry *e = &st->table[(idx + i) & (st->cap - 1)];
        if (!e->used) return e;
        if (hb_det_key_equal(&e->key, key)) return e;
    }

    uint32_t best = st->evict_cursor & (st->cap - 1);
    uint64_t best_ts = st->table[best].last_seen;
    for (uint32_t i = 0; i < DET_EVICT_SCAN; i++) {
        uint32_t idx2 = (st->evict_cursor + i) & (st->cap - 1);
        if (!st->table[idx2].used) {
            st->evict_cursor = idx2 + 1;
            return &st->table[idx2];
        }
        if (st->table[idx2].last_seen < best_ts) {
            best_ts = st->table[idx2].last_seen;
            best = idx2;
        }
    }
    st->evict_cursor = best + 1;
    return &st->table[best];
}

static void det_decay(hb_det_entry *e, uint64_t now, int32_t decay_per_sec) {
    if (!e || !e->used || now <= e->last_seen) return;
    if (decay_per_sec <= 0) {
        e->last_seen = now;
        return;
    }
    uint64_t dt = now - e->last_seen;
    int64_t drop = (int64_t)dt * (int64_t)decay_per_sec;
    if (drop >= e->score) e->score = 0;
    else e->score -= drop;
    e->last_seen = now;
}

static void det_score_add(hb_det_entry *e, int32_t signal_score, uint32_t confidence) {
    if (!e) return;
    int64_t add = (int64_t)signal_score * (int64_t)confidence;
    add = (add + 99) / 100;
    e->score += add;
    if (e->score > DET_MAX_SCORE) e->score = DET_MAX_SCORE;
}

static int key_from_ip_str(const char *ip_str, hb_det_key *out) {
    if (!ip_str || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (strchr(ip_str, ':')) {
        struct in6_addr a6;
        if (inet_pton(AF_INET6, ip_str, &a6) != 1) return -1;
        out->ver = 6;
        memcpy(out->ip, a6.s6_addr, 16);
        return 0;
    }
    struct in_addr a4;
    if (inet_pton(AF_INET, ip_str, &a4) != 1) return -1;
    out->ver = 4;
    memcpy(out->ip, &a4.s_addr, 4);
    return 0;
}

static uint32_t telemetry_confidence(const hb_telemetry_event *ev) {
    if (!ev) return 0;
    if (ev->reason == 4 || ev->reason == 5) return 98;
    if (ev->protocol != IPPROTO_TCP) return 0;
    if (!(ev->tcp_flags & TCP_FLAG_SYN)) return 0;
    if (ev->tcp_flags & TCP_FLAG_ACK) return 0;

    uint32_t c = 45;
    if (ev->dst_port < 1024) c += 10;
    if (ev->dst_port == 22 || ev->dst_port == 3389 || ev->dst_port == 3306 || ev->dst_port == 5432 || ev->dst_port == 6379) c += 20;
    if (ev->pkt_len <= 90) c += 5;
    if (c > 95) c = 95;
    return c;
}

static int32_t telemetry_signal_score(const hb_detection_state *st, const hb_telemetry_event *ev, int *kind) {
    if (!st || !ev) return 0;
    if (ev->reason == 5) {
        if (kind) *kind = 2;
        return st->portscan_score;
    }
    if (ev->reason == 4) {
        if (kind) *kind = 1;
        return st->syn_score;
    }
    if (kind) *kind = 1;
    return st->syn_score;
}

static uint32_t journal_confidence(const char *filter_name) {
    if (!filter_name || !*filter_name) return 0;
    if (strstr(filter_name, "sshd") || strstr(filter_name, "ssh")) return 92;
    if (strstr(filter_name, "auth")) return 88;
    return 78;
}

static int32_t journal_signal_score(const hb_detection_state *st, const char *filter_name, int *kind) {
    if (!st) return 0;
    if (kind) *kind = 4;
    if (filter_name && (strstr(filter_name, "sshd") || strstr(filter_name, "ssh"))) {
        if (kind) *kind = 3;
        return st->ssh_score;
    }
    return st->journal_score;
}

static int det_should_forward(hb_detection_state *st, hb_det_entry *e, uint32_t confidence, uint64_t now) {
    if (!st || !e) return 0;
    if (confidence < st->min_confidence) return 0;
    if (st->forward_cooldown_sec > 0 && now > e->last_forward && (now - e->last_forward) < st->forward_cooldown_sec) return 0;
    if (confidence >= st->high_confidence_bypass) return 1;
    return e->score >= st->score_threshold;
}

static void det_apply_signal(hb_detection_state *st, hb_det_entry *e, const hb_det_signal *s, uint64_t now) {
    if (!st || !e || !s) return;
    if (!e->used || !hb_det_key_equal(&e->key, &s->key)) {
        memset(e, 0, sizeof(*e));
        e->used = 1;
        e->key = s->key;
        e->last_seen = now;
    } else {
        det_decay(e, now, st->decay_per_sec);
    }
    det_score_add(e, s->signal_score, s->confidence);
    if (s->kind == 1) e->syn_hits++;
    else if (s->kind == 2) e->portscan_hits++;
    else if (s->kind == 3) e->ssh_hits++;
    else if (s->kind == 4) e->journal_hits++;
}

int hb_detection_init(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_detection_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;

    st->cap = DET_TABLE_CAP;
    st->table = calloc(st->cap, sizeof(hb_det_entry));
    if (!st->table) {
        free(st);
        return -1;
    }
    detection_load_cfg(st);

    pthread_mutex_lock(&ctx->detection_mu);
    ctx->detection = st;
    pthread_mutex_unlock(&ctx->detection_mu);

    hb_log_info("detection initialized min_conf=%u score_threshold=%d", st->min_confidence, st->score_threshold);
    return 0;
}

int hb_detection_reload(hb_ctx *ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->detection_mu);
    hb_detection_state *st = (hb_detection_state *)ctx->detection;
    if (!st) {
        pthread_mutex_unlock(&ctx->detection_mu);
        return -1;
    }
    detection_load_cfg(st);
    pthread_mutex_unlock(&ctx->detection_mu);
    hb_log_info("detection reloaded min_conf=%u score_threshold=%d", st->min_confidence, st->score_threshold);
    return 0;
}

void hb_detection_free(hb_ctx *ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&ctx->detection_mu);
    hb_detection_state *st = (hb_detection_state *)ctx->detection;
    ctx->detection = NULL;
    pthread_mutex_unlock(&ctx->detection_mu);
    if (!st) return;
    free(st->table);
    free(st);
}

void hb_detection_on_telemetry(hb_ctx *ctx, const hb_telemetry_event *ev) {
    if (!ctx || !ev) return;
    if (ev->action != 0) return;

    hb_det_signal s;
    memset(&s, 0, sizeof(s));
    hb_det_key_from_event(&s.key, ev);
    s.confidence = telemetry_confidence(ev);
    if (s.confidence == 0) return;

    int should_forward = 0;
    uint64_t now = hb_mono_sec();
    pthread_mutex_lock(&ctx->detection_mu);
    hb_detection_state *st = (hb_detection_state *)ctx->detection;
    if (st) {
        s.signal_score = telemetry_signal_score(st, ev, &s.kind);
        hb_det_entry *e = det_find_entry(st, &s.key);
        if (e && s.signal_score > 0) {
            det_apply_signal(st, e, &s, now);
            should_forward = det_should_forward(st, e, s.confidence, now);
            if (should_forward) e->last_forward = now;
        }
    }
    pthread_mutex_unlock(&ctx->detection_mu);

    if (should_forward) {
        hb_jails_on_telemetry(ctx, ev);
    }
}

void hb_detection_on_filter_fail(hb_ctx *ctx, const char *filter_name, const char *ip_str) {
    if (!ctx || !filter_name || !*filter_name || !ip_str || !*ip_str) return;

    hb_det_signal s;
    memset(&s, 0, sizeof(s));
    if (key_from_ip_str(ip_str, &s.key) != 0) return;
    s.confidence = journal_confidence(filter_name);
    if (s.confidence == 0) return;

    int should_forward = 0;
    uint64_t now = hb_mono_sec();
    pthread_mutex_lock(&ctx->detection_mu);
    hb_detection_state *st = (hb_detection_state *)ctx->detection;
    if (st) {
        s.signal_score = journal_signal_score(st, filter_name, &s.kind);
        hb_det_entry *e = det_find_entry(st, &s.key);
        if (e && s.signal_score > 0) {
            det_apply_signal(st, e, &s, now);
            should_forward = det_should_forward(st, e, s.confidence, now);
            if (should_forward) e->last_forward = now;
        }
    }
    pthread_mutex_unlock(&ctx->detection_mu);

    if (should_forward) {
        hb_jails_on_filter_fail(ctx, filter_name, ip_str);
    }
}
