// SPDX-License-Identifier: MIT

#include "filters.h"

#include "../log.h"
#include "../jails/ini.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HB_MAX_FILTERS 128
#define HB_MAX_PATTERNS 32
#define HB_MAX_IGNORE_PATTERNS 16
#define HB_MAX_PREFILTERS 8

typedef struct {
    int used;
    int flags;
    regex_t re;
} hb_re;

typedef struct {
    char name[64];
    int enabled;
    char syslog_identifier[64];
    char prefilters[HB_MAX_PREFILTERS][64];
    uint8_t prefilters_len;
    hb_re patterns[HB_MAX_PATTERNS];
    uint8_t patterns_len;
    hb_re ignore_patterns[HB_MAX_IGNORE_PATTERNS];
    uint8_t ignore_patterns_len;
    int datepattern_mode; // 0 none, 1 syslog, 2 iso8601, 3 custom regex
    hb_re datepattern_re;
    int ip_group;
} hb_filter;

typedef struct {
    hb_filter filters[HB_MAX_FILTERS];
    uint16_t len;
} hb_filters_state;

static uint32_t fnv1a32(const uint8_t *data, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
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

static void parse_prefilter_list(hb_filter *f, const char *v) {
    if (!f || !v) return;
    const char *p = v;
    while (*p && f->prefilters_len < HB_MAX_PREFILTERS) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',' && *end != '\n' && *end != '\r') end++;
        size_t n = (size_t)(end - p);
        while (n > 0 && isspace((unsigned char)p[n - 1])) n--;
        if (n > 0 && n < sizeof(f->prefilters[0])) {
            memcpy(f->prefilters[f->prefilters_len], p, n);
            f->prefilters[f->prefilters_len][n] = '\0';
            f->prefilters_len++;
        }
        p = end;
        while (*p && *p != ',') p++;
    }
}

static int contains_any_prefilter(const hb_filter *f, const char *msg) {
    if (!f || !msg) return 0;
    if (f->prefilters_len == 0) return 1;
    for (uint8_t i = 0; i < f->prefilters_len; i++) {
        if (f->prefilters[i][0] && strstr(msg, f->prefilters[i])) return 1;
    }
    return 0;
}

static hb_filter *find_or_add_filter(hb_filters_state *st, const char *name) {
    if (!st || !name || !*name) return NULL;
    for (uint16_t i = 0; i < st->len; i++) {
        if (!strcmp(st->filters[i].name, name)) return &st->filters[i];
    }
    if (st->len >= HB_MAX_FILTERS) return NULL;
    hb_filter *f = &st->filters[st->len++];
    memset(f, 0, sizeof(*f));
    strncpy(f->name, name, sizeof(f->name) - 1);
    f->enabled = 1;
    f->ip_group = 1;
    return f;
}

static int add_pattern(hb_filter *f, const char *pattern, int flags) {
    if (!f || !pattern || !*pattern) return -1;
    if (f->patterns_len >= HB_MAX_PATTERNS) return -1;

    hb_re *r = &f->patterns[f->patterns_len++];
    memset(r, 0, sizeof(*r));
    r->flags = flags;
    int rc = regcomp(&r->re, pattern, flags);
    if (rc != 0) {
        char eb[256];
        regerror(rc, &r->re, eb, sizeof(eb));
        hb_log_error("filter %s: regex compile failed: %s", f->name, eb);
        f->patterns_len--;
        return -1;
    }
    r->used = 1;
    return 0;
}

static int add_ignore_pattern(hb_filter *f, const char *pattern, int flags) {
    if (!f || !pattern || !*pattern) return -1;
    if (f->ignore_patterns_len >= HB_MAX_IGNORE_PATTERNS) return -1;

    hb_re *r = &f->ignore_patterns[f->ignore_patterns_len++];
    memset(r, 0, sizeof(*r));
    r->flags = flags;
    int rc = regcomp(&r->re, pattern, flags | REG_NOSUB);
    if (rc != 0) {
        char eb[256];
        regerror(rc, &r->re, eb, sizeof(eb));
        hb_log_error("filter %s: ignoreregex compile failed: %s", f->name, eb);
        f->ignore_patterns_len--;
        return -1;
    }
    r->used = 1;
    return 0;
}

static int month3(const char *s) {
    static const char *m[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (!s) return 0;
    for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        if (strncmp(s, m[i], 3) == 0) return 1;
    }
    return 0;
}

static const char *strip_syslog_date(const char *msg) {
    if (!msg || strlen(msg) < 16) return msg;
    if (!month3(msg)) return msg;
    if (msg[3] != ' ') return msg;
    if (!(isdigit((unsigned char)msg[4]) || msg[4] == ' ')) return msg;
    if (!(isdigit((unsigned char)msg[5]) || msg[5] == ' ')) return msg;
    if (msg[6] != ' ') return msg;
    if (!isdigit((unsigned char)msg[7]) || !isdigit((unsigned char)msg[8])) return msg;
    if (msg[9] != ':') return msg;
    if (!isdigit((unsigned char)msg[10]) || !isdigit((unsigned char)msg[11])) return msg;
    if (msg[12] != ':') return msg;
    if (!isdigit((unsigned char)msg[13]) || !isdigit((unsigned char)msg[14])) return msg;
    if (msg[15] != ' ') return msg;

    const char *p = msg + 16;
    while (*p == ' ') p++;
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    return *p ? p : msg;
}

static const char *strip_iso8601_date(const char *msg) {
    if (!msg || strlen(msg) < 20) return msg;
    if (!isdigit((unsigned char)msg[0]) || !isdigit((unsigned char)msg[1]) ||
        !isdigit((unsigned char)msg[2]) || !isdigit((unsigned char)msg[3])) return msg;
    if (msg[4] != '-') return msg;
    if (!isdigit((unsigned char)msg[5]) || !isdigit((unsigned char)msg[6])) return msg;
    if (msg[7] != '-') return msg;
    if (!isdigit((unsigned char)msg[8]) || !isdigit((unsigned char)msg[9])) return msg;
    if (!(msg[10] == 'T' || msg[10] == ' ')) return msg;
    if (!isdigit((unsigned char)msg[11]) || !isdigit((unsigned char)msg[12])) return msg;
    if (msg[13] != ':') return msg;
    if (!isdigit((unsigned char)msg[14]) || !isdigit((unsigned char)msg[15])) return msg;
    if (msg[16] != ':') return msg;
    if (!isdigit((unsigned char)msg[17]) || !isdigit((unsigned char)msg[18])) return msg;

    const char *p = msg;
    while (*p && !isspace((unsigned char)*p)) p++;
    while (*p == ' ') p++;
    return *p ? p : msg;
}

static void set_datepattern(hb_filter *f, const char *value) {
    if (!f) return;
    if (f->datepattern_re.used) {
        regfree(&f->datepattern_re.re);
        memset(&f->datepattern_re, 0, sizeof(f->datepattern_re));
    }

    if (!value || !*value || !strcmp(value, "none")) {
        f->datepattern_mode = 0;
        return;
    }
    if (!strcmp(value, "syslog")) {
        f->datepattern_mode = 1;
        return;
    }
    if (!strcmp(value, "iso8601")) {
        f->datepattern_mode = 2;
        return;
    }

    int rc = regcomp(&f->datepattern_re.re, value, REG_EXTENDED);
    if (rc != 0) {
        char eb[256];
        regerror(rc, &f->datepattern_re.re, eb, sizeof(eb));
        hb_log_error("filter %s: datepattern compile failed: %s", f->name, eb);
        f->datepattern_mode = 0;
        return;
    }
    f->datepattern_re.used = 1;
    f->datepattern_mode = 3;
}

static const char *normalized_message(const hb_filter *f, const char *message) {
    if (!f || !message) return message;
    if (f->datepattern_mode == 1) return strip_syslog_date(message);
    if (f->datepattern_mode == 2) return strip_iso8601_date(message);
    if (f->datepattern_mode == 3 && f->datepattern_re.used) {
        regmatch_t m;
        if (regexec(&f->datepattern_re.re, message, 1, &m, 0) == 0 && m.rm_so == 0 && m.rm_eo > 0) {
            const char *p = message + m.rm_eo;
            while (*p == ' ') p++;
            if (*p) return p;
        }
    }
    return message;
}

static int matches_any_ignore(const hb_filter *f, const char *message) {
    if (!f || !message) return 0;
    for (uint8_t i = 0; i < f->ignore_patterns_len; i++) {
        const hb_re *r = &f->ignore_patterns[i];
        if (!r->used) continue;
        if (regexec(&r->re, message, 0, NULL, 0) == 0) return 1;
    }
    return 0;
}

static void on_filter_kv(void *userdata, const char *section, const char *key, const char *value) {
    hb_filters_state *st = (hb_filters_state *)userdata;
    if (!st || !section || !*section || !key || !*key) return;

    hb_filter *f = find_or_add_filter(st, section);
    if (!f) return;

    if (!strcmp(key, "enabled")) {
        int v = f->enabled;
        if (parse_on_off(value, &v)) f->enabled = v;
        return;
    }

    if (!strcmp(key, "syslog_identifier")) {
        if (value && *value) {
            strncpy(f->syslog_identifier, value, sizeof(f->syslog_identifier) - 1);
            f->syslog_identifier[sizeof(f->syslog_identifier) - 1] = '\0';
        } else {
            f->syslog_identifier[0] = '\0';
        }
        return;
    }

    if (!strcmp(key, "prefilter")) {
        if (!value || !*value) {
            f->prefilters_len = 0;
            return;
        }
        parse_prefilter_list(f, value);
        return;
    }

    if (!strcmp(key, "ip_group")) {
        int g = atoi(value);
        if (g >= 1 && g <= 15) f->ip_group = g;
        return;
    }

    if (!strcmp(key, "regex")) {
        (void)add_pattern(f, value, REG_EXTENDED);
        return;
    }

    if (!strcmp(key, "regexi")) {
        (void)add_pattern(f, value, REG_EXTENDED | REG_ICASE);
        return;
    }

    if (!strcmp(key, "ignoreregex")) {
        (void)add_ignore_pattern(f, value, REG_EXTENDED);
        return;
    }

    if (!strcmp(key, "ignoreregi")) {
        (void)add_ignore_pattern(f, value, REG_EXTENDED | REG_ICASE);
        return;
    }

    if (!strcmp(key, "datepattern")) {
        set_datepattern(f, value);
        return;
    }
}

static void filters_state_free(hb_filters_state *st) {
    if (!st) return;
    for (uint16_t i = 0; i < st->len; i++) {
        hb_filter *f = &st->filters[i];
        for (uint8_t j = 0; j < f->patterns_len; j++) {
            if (f->patterns[j].used) regfree(&f->patterns[j].re);
            f->patterns[j].used = 0;
        }
        f->patterns_len = 0;
        for (uint8_t j = 0; j < f->ignore_patterns_len; j++) {
            if (f->ignore_patterns[j].used) regfree(&f->ignore_patterns[j].re);
            f->ignore_patterns[j].used = 0;
        }
        f->ignore_patterns_len = 0;
        if (f->datepattern_re.used) {
            regfree(&f->datepattern_re.re);
            f->datepattern_re.used = 0;
        }
    }
    free(st);
}

static int ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    size_t n = strlen(s);
    size_t m = strlen(suffix);
    if (m > n) return 0;
    return memcmp(s + (n - m), suffix, m) == 0;
}

static int load_filters_dir(hb_filters_state *st, const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!ent->d_name || ent->d_name[0] == '.') continue;
        if (!ends_with(ent->d_name, ".conf")) continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir_path, ent->d_name);
        (void)hb_ini_parse_file(path, on_filter_kv, st);
    }

    closedir(d);
    return 0;
}

static hb_filters_state *filters_state_build(void) {
    hb_filters_state *st = calloc(1, sizeof(*st));
    if (!st) return NULL;

    const char *dir = getenv("HONEYBAN_FILTERS_DIR");
    if (!dir || !*dir) dir = "/etc/honeyban/filters.d";

    (void)load_filters_dir(st, dir);

    // Built-in default sshd filter if none provided.
    // This keeps the project usable out-of-the-box, while still allowing users to override via filters.d.
    if (st->len == 0) {
        hb_filter *f = find_or_add_filter(st, "sshd");
        if (f) {
            strncpy(f->syslog_identifier, "sshd", sizeof(f->syslog_identifier) - 1);
            parse_prefilter_list(f, "Failed password,Invalid user,authentication failure,Failed publickey,maximum authentication attempts exceeded");
            (void)add_pattern(f, "Failed password for( invalid user)? .* from ([0-9A-Fa-f:.]+) port [0-9]+", REG_EXTENDED);
            (void)add_pattern(f, "Invalid user .* from ([0-9A-Fa-f:.]+) port [0-9]+", REG_EXTENDED);
            (void)add_pattern(f, "Failed publickey for( invalid user)? .* from ([0-9A-Fa-f:.]+) port [0-9]+", REG_EXTENDED);
            (void)add_pattern(f, "maximum authentication attempts exceeded for .* from ([0-9A-Fa-f:.]+) port [0-9]+", REG_EXTENDED);
            (void)add_pattern(f, "authentication failure;.* rhost=([0-9A-Fa-f:.]+)", REG_EXTENDED);
        }
    }

    return st;
}

int hb_filters_load(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_filters_state *st = filters_state_build();
    if (!st) return -1;

    pthread_mutex_lock(&ctx->filters_mu);
    ctx->filters = st;
    pthread_mutex_unlock(&ctx->filters_mu);

    hb_log_info("filters loaded: %u", (unsigned)st->len);
    return 0;
}

int hb_filters_reload(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_filters_state *next = filters_state_build();
    if (!next) return -1;

    pthread_mutex_lock(&ctx->filters_mu);
    hb_filters_state *prev = (hb_filters_state *)ctx->filters;
    ctx->filters = next;
    pthread_mutex_unlock(&ctx->filters_mu);

    if (prev) filters_state_free(prev);

    hb_log_info("filters reloaded: %u", (unsigned)next->len);
    return 0;
}

void hb_filters_free(hb_ctx *ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&ctx->filters_mu);
    hb_filters_state *st = (hb_filters_state *)ctx->filters;
    ctx->filters = NULL;
    pthread_mutex_unlock(&ctx->filters_mu);
    if (st) filters_state_free(st);
}

size_t hb_filters_get_syslog_identifiers(hb_ctx *ctx, char *out_ids, size_t max_ids, size_t stride, uint32_t *out_sig) {
    if (!ctx || !out_ids || stride == 0 || max_ids == 0) {
        if (out_sig) *out_sig = 0;
        return 0;
    }

    pthread_mutex_lock(&ctx->filters_mu);
    const hb_filters_state *st = (const hb_filters_state *)ctx->filters;
    if (!st) {
        pthread_mutex_unlock(&ctx->filters_mu);
        if (out_sig) *out_sig = 0;
        return 0;
    }

    size_t n = 0;
    uint32_t sig = 2166136261u;

    for (uint16_t i = 0; i < st->len; i++) {
        const hb_filter *f = &st->filters[i];
        if (!f->enabled) continue;
        if (!f->syslog_identifier[0]) continue;

        int seen = 0;
        for (size_t k = 0; k < n; k++) {
            const char *s = out_ids + (k * stride);
            if (!strncmp(s, f->syslog_identifier, stride)) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        if (n >= max_ids) break;

        char *dst = out_ids + (n * stride);
        memset(dst, 0, stride);
        strncpy(dst, f->syslog_identifier, stride - 1);
        n++;

        sig ^= fnv1a32((const uint8_t *)f->syslog_identifier, strlen(f->syslog_identifier));
        sig *= 16777619u;
    }

    pthread_mutex_unlock(&ctx->filters_mu);
    if (out_sig) *out_sig = sig;
    return n;
}

static int valid_ip(const char *s) {
    if (!s || !*s) return 0;
    struct in_addr a4;
    if (inet_pton(AF_INET, s, &a4) == 1) return 1;
    struct in6_addr a6;
    if (inet_pton(AF_INET6, s, &a6) == 1) return 1;
    return 0;
}

static int extract_group(const char *msg, const regmatch_t *m, char *out, size_t cap) {
    if (!msg || !m || !out || cap == 0) return -1;
    if (m->rm_so < 0 || m->rm_eo < 0 || m->rm_eo <= m->rm_so) return -1;
    size_t n = (size_t)(m->rm_eo - m->rm_so);
    if (n >= cap) return -1;
    memcpy(out, msg + m->rm_so, n);
    out[n] = '\0';
    return 0;
}

int hb_filters_match(hb_ctx *ctx, const char *syslog_id, const char *message, char *out_filter, size_t out_filter_cap,
                     char *out_ip, size_t out_ip_cap) {
    if (!ctx || !message || !out_filter || !out_ip) return 0;
    if (out_filter_cap == 0 || out_ip_cap == 0) return 0;
    out_filter[0] = '\0';
    out_ip[0] = '\0';

    pthread_mutex_lock(&ctx->filters_mu);
    const hb_filters_state *st = (const hb_filters_state *)ctx->filters;
    if (!st) {
        pthread_mutex_unlock(&ctx->filters_mu);
        return 0;
    }

    for (uint16_t i = 0; i < st->len; i++) {
        const hb_filter *f = &st->filters[i];
        if (!f->enabled) continue;
        if (f->syslog_identifier[0] && syslog_id && *syslog_id) {
            if (strcmp(f->syslog_identifier, syslog_id) != 0) continue;
        } else if (f->syslog_identifier[0]) {
            continue;
        }
        const char *msg = normalized_message(f, message);
        if (!contains_any_prefilter(f, msg)) continue;
        if (matches_any_ignore(f, msg)) continue;

        for (uint8_t j = 0; j < f->patterns_len; j++) {
            const hb_re *r = &f->patterns[j];
            if (!r->used) continue;
            size_t need = (size_t)f->ip_group + 1;
            if (need < 2) need = 2;
            if (need > 16) need = 16;
            regmatch_t pm[16];
            memset(pm, 0, sizeof(pm));

            int rc = regexec(&r->re, msg, need, pm, 0);
            if (rc != 0) continue;

            char ipbuf[128];
            if (extract_group(msg, &pm[f->ip_group], ipbuf, sizeof(ipbuf)) != 0) continue;
            if (!valid_ip(ipbuf)) continue;

            strncpy(out_filter, f->name, out_filter_cap - 1);
            out_filter[out_filter_cap - 1] = '\0';
            strncpy(out_ip, ipbuf, out_ip_cap - 1);
            out_ip[out_ip_cap - 1] = '\0';

            pthread_mutex_unlock(&ctx->filters_mu);
            return 1;
        }
    }

    pthread_mutex_unlock(&ctx->filters_mu);
    return 0;
}
