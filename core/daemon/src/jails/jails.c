// SPDX-License-Identifier: MIT

#include "jails.h"

#include "../actions/actions.h"
#include "../log.h"
#include "../timeutil.h"
#include "cidr.h"
#include "ini.h"
#include "ipkey.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#define MAX_JAILS 32
#define MAX_PORTS 32
#define MAX_IGNORE 64

#define MAX_PORTS_TRACK 64
#define TABLE_CAP 16384u

#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_SYN 0x02

typedef enum {
    HB_JAIL_DET_SYNFLOOD = 1,
    HB_JAIL_DET_PORTSCAN = 2,
    HB_JAIL_DET_SSH = 3,
    HB_JAIL_DET_JOURNAL = 4,
} hb_jail_detector;

typedef struct {
    int used;
    hb_det_key key;
    uint64_t window_start;
    uint32_t count;
    uint16_t ports[MAX_PORTS_TRACK];
    uint8_t nports;
    uint64_t last_seen;
} hb_jail_entry;

typedef struct {
    char name[64];
    int enabled;
    hb_jail_detector detector;
    char action[64];
    char filter[64]; // for journal detector; if empty, uses jail name

    // fail2ban-like knobs
    uint32_t maxretry;
    uint32_t findtime;
    uint32_t bantime;
    uint32_t ban_level;

    // scope filters
    int proto; // 0 any, IPPROTO_TCP, IPPROTO_UDP
    uint16_t ports[MAX_PORTS];
    uint8_t ports_len;

    hb_cidr ignore[MAX_IGNORE];
    uint8_t ignore_len;

    hb_jail_entry *table;
    uint32_t cap;
    uint32_t evict_cursor;
} hb_jail;

typedef struct {
    hb_jail jails[MAX_JAILS];
    uint8_t len;
} hb_jails_state;

static int parse_detector(const char *s, hb_jail_detector *out) {
    if (!s || !out) return 0;
    if (!strcmp(s, "synflood")) {
        *out = HB_JAIL_DET_SYNFLOOD;
        return 1;
    }
    if (!strcmp(s, "portscan")) {
        *out = HB_JAIL_DET_PORTSCAN;
        return 1;
    }
    if (!strcmp(s, "ssh")) {
        *out = HB_JAIL_DET_SSH;
        return 1;
    }
    if (!strcmp(s, "journal")) {
        *out = HB_JAIL_DET_JOURNAL;
        return 1;
    }
    return 0;
}

static int parse_proto(const char *s) {
    if (!s || !*s) return 0;
    if (!strcmp(s, "tcp")) return IPPROTO_TCP;
    if (!strcmp(s, "udp")) return IPPROTO_UDP;
    if (!strcmp(s, "any")) return 0;
    return 0;
}

static int parse_on_off(const char *s, int *out) {
    if (!s || !*s) return 0;
    if (!strcmp(s, "1") || !strcmp(s, "true") || !strcmp(s, "on") || !strcmp(s, "yes")) {
        *out = 1;
        return 1;
    }
    if (!strcmp(s, "0") || !strcmp(s, "false") || !strcmp(s, "off") || !strcmp(s, "no")) {
        *out = 0;
        return 1;
    }
    return 0;
}

static void parse_ports_list(hb_jail *j, const char *v) {
    if (!j || !v) return;
    j->ports_len = 0;
    const char *p = v;
    while (*p && j->ports_len < MAX_PORTS) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        char *end = NULL;
        long port = strtol(p, &end, 10);
        if (end == p) break;
        if (port > 0 && port <= 65535) {
            j->ports[j->ports_len++] = (uint16_t)port;
        }
        p = end;
        while (*p && *p != ',') p++;
    }
}

static void parse_ignore_list(hb_jail *j, const char *v) {
    if (!j || !v) return;
    j->ignore_len = 0;
    const char *p = v;
    while (*p && j->ignore_len < MAX_IGNORE) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',' && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') end++;
        char tmp[128];
        size_t n = (size_t)(end - p);
        if (n > 0 && n < sizeof(tmp)) {
            memcpy(tmp, p, n);
            tmp[n] = '\0';
            hb_cidr c;
            if (hb_cidr_parse(tmp, &c) == 0) {
                j->ignore[j->ignore_len++] = c;
            }
        }
        p = end;
        while (*p && *p != ',') p++;
    }
}

static int port_in_scope(const hb_jail *j, uint16_t dport) {
    if (!j) return 0;
    if (j->ports_len == 0) return 1;
    for (uint8_t i = 0; i < j->ports_len; i++) {
        if (j->ports[i] == dport) return 1;
    }
    return 0;
}

static int ip_ignored(const hb_jail *j, const char *ip_str) {
    if (!j || !ip_str) return 0;
    for (uint8_t i = 0; i < j->ignore_len; i++) {
        if (hb_cidr_match_ip_str(&j->ignore[i], ip_str)) return 1;
    }
    return 0;
}

static hb_jail_entry *jail_find_entry(hb_jail *j, const hb_det_key *k) {
    uint32_t idx = hb_det_key_hash(k) & (j->cap - 1);
    for (uint32_t i = 0; i < j->cap; i++) {
        hb_jail_entry *e = &j->table[(idx + i) & (j->cap - 1)];
        if (!e->used) return e;
        if (hb_det_key_equal(&e->key, k)) return e;
    }

    uint32_t best = j->evict_cursor & (j->cap - 1);
    uint64_t best_ts = j->table[best].last_seen;
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t k2 = (j->evict_cursor + i) & (j->cap - 1);
        if (!j->table[k2].used) {
            j->evict_cursor = k2 + 1;
            return &j->table[k2];
        }
        if (j->table[k2].last_seen < best_ts) {
            best_ts = j->table[k2].last_seen;
            best = k2;
        }
    }
    j->evict_cursor = best + 1;
    return &j->table[best];
}

static int port_seen(const hb_jail_entry *e, uint16_t port) {
    for (uint8_t i = 0; i < e->nports; i++) {
        if (e->ports[i] == port) return 1;
    }
    return 0;
}

static void jail_apply_action(hb_ctx *ctx, const hb_jail *j, const char *ip_str, const hb_telemetry_event *ev) {
    int ttl = (int)j->bantime;
    int level = (int)j->ban_level;
    if (level == 0) level = 3;
    const char *action_name = j->action[0] ? j->action : "banip";
    const char *filter_name = j->filter[0] ? j->filter : j->name;
    const char *proto = "tcp";
    if (j->proto == IPPROTO_UDP) proto = "udp";
    else if (ev && ev->protocol == IPPROTO_UDP) proto = "udp";
    int port = ev ? (int)ev->dst_port : (j->ports_len ? (int)j->ports[0] : 0);

    (void)hb_actions_apply_ban(ctx, action_name, j->name, filter_name, ip_str, proto, port, ttl, level);
}

static void jail_on_rate(hb_ctx *ctx, hb_jail *j, const hb_det_key *k, const char *ip_str, const hb_telemetry_event *ev) {
    uint64_t now = hb_mono_sec();
    hb_jail_entry *e = jail_find_entry(j, k);
    if (!e->used || !hb_det_key_equal(&e->key, k)) {
        memset(e, 0, sizeof(*e));
        e->used = 1;
        e->key = *k;
        e->window_start = now;
        e->count = 1;
        e->last_seen = now;
        return;
    }
    e->last_seen = now;
    if (now - e->window_start >= j->findtime) {
        e->window_start = now;
        e->count = 1;
        return;
    }
    e->count++;
    if (e->count < j->maxretry) return;

    hb_log_info("jail trigger name=%s ip=%s", j->name, ip_str);
    jail_apply_action(ctx, j, ip_str, ev);
    e->window_start = now;
    e->count = 0;
}

static void jail_on_portscan(hb_ctx *ctx, hb_jail *j, const hb_det_key *k, const char *ip_str, const hb_telemetry_event *ev) {
    uint16_t dport = ev ? ev->dst_port : 0;
    if (dport == 0) return;

    uint64_t now = hb_mono_sec();
    hb_jail_entry *e = jail_find_entry(j, k);
    if (!e->used || !hb_det_key_equal(&e->key, k)) {
        memset(e, 0, sizeof(*e));
        e->used = 1;
        e->key = *k;
        e->window_start = now;
        e->ports[0] = dport;
        e->nports = 1;
        e->last_seen = now;
        return;
    }
    e->last_seen = now;
    if (now - e->window_start >= j->findtime) {
        e->window_start = now;
        e->nports = 1;
        e->ports[0] = dport;
        return;
    }
    if (port_seen(e, dport)) return;
    if (e->nports < MAX_PORTS_TRACK) e->ports[e->nports++] = dport;
    if (e->nports < j->maxretry) return;

    hb_log_info("jail trigger name=%s ip=%s", j->name, ip_str);
    jail_apply_action(ctx, j, ip_str, ev);
    e->window_start = now;
    e->nports = 0;
}

static void ini_on_kv(void *userdata, const char *section, const char *key, const char *value) {
    hb_jails_state *st = (hb_jails_state *)userdata;
    if (!st || !section || !*section) return;
    if (st->len >= MAX_JAILS) return;

    hb_jail *j = NULL;
    for (uint8_t i = 0; i < st->len; i++) {
        if (!strcmp(st->jails[i].name, section)) {
            j = &st->jails[i];
            break;
        }
    }
    if (!j) {
        j = &st->jails[st->len++];
        memset(j, 0, sizeof(*j));
        strncpy(j->name, section, sizeof(j->name) - 1);
        j->enabled = 1;
        j->detector = HB_JAIL_DET_SYNFLOOD;
        strncpy(j->action, "banip", sizeof(j->action) - 1);
        j->maxretry = 20;
        j->findtime = 10;
        j->bantime = 600;
        j->ban_level = 3;
        j->proto = 0;
        j->cap = TABLE_CAP;
    }

    if (!strcmp(key, "enabled")) {
        int v = j->enabled;
        if (parse_on_off(value, &v)) j->enabled = v;
        return;
    }
    if (!strcmp(key, "detector")) {
        (void)parse_detector(value, &j->detector);
        return;
    }
    if (!strcmp(key, "action")) {
        if (value && *value) {
            strncpy(j->action, value, sizeof(j->action) - 1);
            j->action[sizeof(j->action) - 1] = '\0';
        } else {
            strncpy(j->action, "banip", sizeof(j->action) - 1);
            j->action[sizeof(j->action) - 1] = '\0';
        }
        return;
    }
    if (!strcmp(key, "filter")) {
        if (value && *value) {
            strncpy(j->filter, value, sizeof(j->filter) - 1);
            j->filter[sizeof(j->filter) - 1] = '\0';
        } else {
            j->filter[0] = '\0';
        }
        return;
    }
    if (!strcmp(key, "maxretry")) {
        j->maxretry = (uint32_t)atoi(value);
        return;
    }
    if (!strcmp(key, "findtime")) {
        j->findtime = (uint32_t)atoi(value);
        return;
    }
    if (!strcmp(key, "bantime")) {
        j->bantime = (uint32_t)atoi(value);
        return;
    }
    if (!strcmp(key, "ban_level")) {
        j->ban_level = (uint32_t)atoi(value);
        return;
    }
    if (!strcmp(key, "protocol")) {
        j->proto = parse_proto(value);
        return;
    }
    if (!strcmp(key, "ports")) {
        parse_ports_list(j, value);
        return;
    }
    if (!strcmp(key, "ignoreip")) {
        parse_ignore_list(j, value);
        return;
    }
}

static void default_jails(hb_jails_state *st, hb_ctx *ctx) {
    // SSH auth jail (journald filters)
    hb_jail *ssh = &st->jails[st->len++];
    memset(ssh, 0, sizeof(*ssh));
    strncpy(ssh->name, "ssh", sizeof(ssh->name) - 1);
    ssh->enabled = 1;
    ssh->detector = HB_JAIL_DET_JOURNAL;
    strncpy(ssh->action, "banip", sizeof(ssh->action) - 1);
    strncpy(ssh->filter, "sshd", sizeof(ssh->filter) - 1);
    ssh->maxretry = ctx->cfg.ssh_threshold ? ctx->cfg.ssh_threshold : 8;
    ssh->findtime = ctx->cfg.ssh_window_sec ? ctx->cfg.ssh_window_sec : 120;
    ssh->bantime = ctx->cfg.autoban_ttl ? ctx->cfg.autoban_ttl : 3600;
    ssh->ban_level = ctx->cfg.autoban_level ? ctx->cfg.autoban_level : 3;
    ssh->proto = IPPROTO_TCP;
    ssh->ports[0] = 22;
    ssh->ports_len = 1;
    ssh->cap = TABLE_CAP;

    hb_jail *ps = &st->jails[st->len++];
    memset(ps, 0, sizeof(*ps));
    strncpy(ps->name, "portscan", sizeof(ps->name) - 1);
    ps->enabled = 1;
    ps->detector = HB_JAIL_DET_PORTSCAN;
    strncpy(ps->action, "banip", sizeof(ps->action) - 1);
    ps->maxretry = ctx->cfg.portscan_threshold ? ctx->cfg.portscan_threshold : 20;
    ps->findtime = ctx->cfg.portscan_window_sec ? ctx->cfg.portscan_window_sec : 10;
    ps->bantime = ctx->cfg.autoban_ttl ? ctx->cfg.autoban_ttl : 600;
    ps->ban_level = ctx->cfg.autoban_level ? ctx->cfg.autoban_level : 3;
    ps->proto = IPPROTO_TCP;
    ps->cap = TABLE_CAP;

    hb_jail *syn = &st->jails[st->len++];
    memset(syn, 0, sizeof(*syn));
    strncpy(syn->name, "synflood", sizeof(syn->name) - 1);
    syn->enabled = 1;
    syn->detector = HB_JAIL_DET_SYNFLOOD;
    strncpy(syn->action, "banip", sizeof(syn->action) - 1);
    syn->maxretry = ctx->cfg.syn_threshold ? ctx->cfg.syn_threshold : 200;
    syn->findtime = ctx->cfg.syn_window_sec ? ctx->cfg.syn_window_sec : 1;
    syn->bantime = ctx->cfg.autoban_ttl ? ctx->cfg.autoban_ttl : 300;
    syn->ban_level = ctx->cfg.autoban_level ? ctx->cfg.autoban_level : 3;
    syn->proto = IPPROTO_TCP;
    syn->cap = TABLE_CAP;
}

static int jail_alloc_tables(hb_jails_state *st) {
    for (uint8_t i = 0; i < st->len; i++) {
        hb_jail *j = &st->jails[i];
        if (j->cap == 0) j->cap = TABLE_CAP;
        // cap must be power of two
        uint32_t cap = 1;
        while (cap < j->cap) cap <<= 1;
        j->cap = cap;
        j->table = calloc(j->cap, sizeof(hb_jail_entry));
        if (!j->table) return -1;
    }
    return 0;
}

static hb_jails_state *jails_state_build(hb_ctx *ctx) {
    if (!ctx) return NULL;
    hb_jails_state *st = calloc(1, sizeof(*st));
    if (!st) return NULL;

    // Try config file (optional).
    const char *path = getenv("HONEYBAN_JAILS_PATH");
    if (!path || !*path) path = "/etc/honeyban/jails.conf";

    if (hb_ini_parse_file(path, ini_on_kv, st) != 0 || st->len == 0) {
        st->len = 0;
        default_jails(st, ctx);
    }

    // Clamp nonsensical values.
    for (uint8_t i = 0; i < st->len; i++) {
        hb_jail *j = &st->jails[i];
        if (j->maxretry == 0) j->maxretry = 1;
        if (j->findtime == 0) j->findtime = 1;
        if (j->ban_level > 5) j->ban_level = 5;
    }

    if (jail_alloc_tables(st) != 0) {
        for (uint8_t i = 0; i < st->len; i++) free(st->jails[i].table);
        free(st);
        return NULL;
    }

    return st;
}

int hb_jails_load(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_jails_state *st = jails_state_build(ctx);
    if (!st) return -1;

    pthread_mutex_lock(&ctx->jails_mu);
    ctx->jails = st;
    pthread_mutex_unlock(&ctx->jails_mu);

    hb_log_info("jails loaded: %u", st->len);
    return 0;
}

int hb_jails_reload(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_jails_state *next = jails_state_build(ctx);
    if (!next) return -1;

    pthread_mutex_lock(&ctx->jails_mu);
    hb_jails_state *prev = (hb_jails_state *)ctx->jails;
    ctx->jails = next;
    pthread_mutex_unlock(&ctx->jails_mu);

    if (prev) {
        for (uint8_t i = 0; i < prev->len; i++) free(prev->jails[i].table);
        free(prev);
    }

    hb_log_info("jails reloaded: %u", next->len);
    return 0;
}

void hb_jails_free(hb_ctx *ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->jails_mu);
    hb_jails_state *st = (hb_jails_state *)ctx->jails;
    ctx->jails = NULL;
    pthread_mutex_unlock(&ctx->jails_mu);

    if (!st) return;
    for (uint8_t i = 0; i < st->len; i++) free(st->jails[i].table);
    free(st);
}

void hb_jails_on_telemetry(hb_ctx *ctx, const hb_telemetry_event *ev) {
    if (!ctx || !ev) return;
    if (!(ctx->cfg.flags & (1u << 4))) return; // telemetry disabled
    if (ev->action != 0) return;
    if (ev->protocol != IPPROTO_TCP) return;
    if (!(ev->tcp_flags & TCP_FLAG_SYN)) return;
    if (ev->tcp_flags & TCP_FLAG_ACK) return;

    pthread_mutex_lock(&ctx->jails_mu);
    hb_jails_state *st = (hb_jails_state *)ctx->jails;
    if (!st) {
        pthread_mutex_unlock(&ctx->jails_mu);
        return;
    }

    hb_det_key k;
    hb_det_key_from_event(&k, ev);
    char ipbuf[128];
    if (hb_det_key_to_string(&k, ipbuf, sizeof(ipbuf)) != 0) {
        pthread_mutex_unlock(&ctx->jails_mu);
        return;
    }

    for (uint8_t i = 0; i < st->len; i++) {
        hb_jail *j = &st->jails[i];
        if (!j->enabled) continue;

        if (j->proto && j->proto != ev->protocol) continue;

        if (ip_ignored(j, ipbuf)) continue;

        if (j->detector == HB_JAIL_DET_SYNFLOOD) {
            jail_on_rate(ctx, j, &k, ipbuf, ev);
            continue;
        }
        if (j->detector == HB_JAIL_DET_PORTSCAN) {
            jail_on_portscan(ctx, j, &k, ipbuf, ev);
            continue;
        }
        if (j->detector == HB_JAIL_DET_SSH) {
            if (!port_in_scope(j, ev->dst_port)) continue;
            jail_on_rate(ctx, j, &k, ipbuf, ev);
            continue;
        }
    }

    pthread_mutex_unlock(&ctx->jails_mu);
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

void hb_jails_on_filter_fail(hb_ctx *ctx, const char *filter_name, const char *ip_str) {
    if (!ctx || !filter_name || !*filter_name || !ip_str || !*ip_str) return;
    if (!(ctx->cfg.flags & (1u << 5))) return; // journal detector disabled

    hb_det_key k;
    if (key_from_ip_str(ip_str, &k) != 0) return;

    pthread_mutex_lock(&ctx->jails_mu);
    hb_jails_state *st = (hb_jails_state *)ctx->jails;
    if (!st) {
        pthread_mutex_unlock(&ctx->jails_mu);
        return;
    }

    for (uint8_t i = 0; i < st->len; i++) {
        hb_jail *j = &st->jails[i];
        if (!j->enabled) continue;
        if (j->detector != HB_JAIL_DET_JOURNAL) continue;

        const char *f = j->filter[0] ? j->filter : j->name;
        if (strcmp(f, filter_name) != 0) continue;

        if (ip_ignored(j, ip_str)) continue;
        jail_on_rate(ctx, j, &k, ip_str, NULL);
    }

    pthread_mutex_unlock(&ctx->jails_mu);
}
