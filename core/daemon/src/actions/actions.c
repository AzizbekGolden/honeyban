// SPDX-License-Identifier: MIT

#include "actions.h"

#include "../bans.h"
#include "../jails/ini.h"
#include "../log.h"

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dirent.h>

#define HB_MAX_ACTIONS 128
#define HB_MAX_ACTION_JOBS 256
#define HB_ACTION_CMD_MAX 768

typedef enum {
    HB_ACTION_BASE_UNKNOWN = -1,
    HB_ACTION_BASE_NONE = 0,
    HB_ACTION_BASE_BAN_IP = 1,
    HB_ACTION_BASE_BAN_IP_PORT = 2,
    HB_ACTION_BASE_BLOCK_PORT = 3,
} hb_action_base;

typedef struct {
    char name[64];
    int enabled;
    hb_action_base base;
    char ban_cmd[HB_ACTION_CMD_MAX];
    uint32_t timeout_ms;
} hb_action_def;

typedef struct {
    char cmd[HB_ACTION_CMD_MAX];
    char action[64];
    uint32_t timeout_ms;
} hb_action_job;

typedef struct {
    hb_action_def defs[HB_MAX_ACTIONS];
    uint16_t defs_len;

    pthread_mutex_t q_mu;
    pthread_cond_t q_cv;
    pthread_t worker_thread;
    int worker_started;
    int worker_running;

    hb_action_job jobs[HB_MAX_ACTION_JOBS];
    uint16_t jobs_head;
    uint16_t jobs_len;
} hb_actions_state;

typedef struct {
    const char *action;
    const char *jail;
    const char *filter;
    const char *ip;
    const char *proto;
    int port;
    int ttl;
    int level;
} hb_action_args;

static uint32_t env_u32(const char *key, uint32_t defv, uint32_t minv, uint32_t maxv) {
    const char *s = getenv(key);
    if (!s || !*s) return defv;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0') return defv;
    if (v < minv) v = minv;
    if (v > maxv) v = maxv;
    return (uint32_t)v;
}

static int parse_on_off(const char *s, int *out) {
    if (!s || !*s || !out) return 0;
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

static hb_action_base parse_base(const char *s) {
    if (!s || !*s) return HB_ACTION_BASE_UNKNOWN;
    if (!strcmp(s, "none")) return HB_ACTION_BASE_NONE;
    if (!strcmp(s, "banip")) return HB_ACTION_BASE_BAN_IP;
    if (!strcmp(s, "banipport")) return HB_ACTION_BASE_BAN_IP_PORT;
    if (!strcmp(s, "blockport")) return HB_ACTION_BASE_BLOCK_PORT;
    return HB_ACTION_BASE_UNKNOWN;
}

static hb_action_base fallback_base(const char *action_name) {
    hb_action_base b = parse_base(action_name);
    if (b == HB_ACTION_BASE_UNKNOWN) return HB_ACTION_BASE_BAN_IP;
    return b;
}

static int ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    size_t n = strlen(s);
    size_t m = strlen(suffix);
    if (m > n) return 0;
    return memcmp(s + (n - m), suffix, m) == 0;
}

typedef struct {
    hb_actions_state *st;
    uint32_t default_timeout_ms;
} hb_action_parse_ctx;

static hb_action_def *find_or_add_def(hb_action_parse_ctx *ctx, const char *name) {
    if (!ctx || !ctx->st || !name || !*name) return NULL;
    for (uint16_t i = 0; i < ctx->st->defs_len; i++) {
        if (!strcmp(ctx->st->defs[i].name, name)) return &ctx->st->defs[i];
    }
    if (ctx->st->defs_len >= HB_MAX_ACTIONS) return NULL;
    hb_action_def *d = &ctx->st->defs[ctx->st->defs_len++];
    memset(d, 0, sizeof(*d));
    strncpy(d->name, name, sizeof(d->name) - 1);
    d->enabled = 1;
    d->timeout_ms = ctx->default_timeout_ms;
    d->base = parse_base(name);
    if (d->base == HB_ACTION_BASE_UNKNOWN) d->base = HB_ACTION_BASE_NONE;
    return d;
}

static void on_action_kv(void *userdata, const char *section, const char *key, const char *value) {
    hb_action_parse_ctx *ctx = (hb_action_parse_ctx *)userdata;
    if (!ctx || !section || !*section || !key || !*key) return;

    hb_action_def *d = find_or_add_def(ctx, section);
    if (!d) return;

    if (!strcmp(key, "enabled")) {
        int v = d->enabled;
        if (parse_on_off(value, &v)) d->enabled = v;
        return;
    }
    if (!strcmp(key, "base")) {
        hb_action_base b = parse_base(value);
        if (b != HB_ACTION_BASE_UNKNOWN) d->base = b;
        return;
    }
    if (!strcmp(key, "ban_cmd")) {
        if (value && *value) {
            strncpy(d->ban_cmd, value, sizeof(d->ban_cmd) - 1);
            d->ban_cmd[sizeof(d->ban_cmd) - 1] = '\0';
        } else {
            d->ban_cmd[0] = '\0';
        }
        return;
    }
    if (!strcmp(key, "timeout_ms")) {
        int ms = atoi(value);
        if (ms < 10) ms = 10;
        if (ms > 30000) ms = 30000;
        d->timeout_ms = (uint32_t)ms;
        return;
    }
}

static int load_actions_dir(hb_action_parse_ctx *ctx, const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!ent->d_name || ent->d_name[0] == '.') continue;
        if (!ends_with(ent->d_name, ".conf")) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir_path, ent->d_name);
        (void)hb_ini_parse_file(path, on_action_kv, ctx);
    }

    closedir(d);
    return 0;
}

static int run_command_with_timeout(const char *cmd, uint32_t timeout_ms) {
    if (!cmd || !*cmd) return 0;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    uint32_t waited = 0;
    const uint32_t tick_ms = 10;
    int status = 0;
    while (waited < timeout_ms) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
            return -1;
        }
        if (r < 0) return -1;
        usleep(tick_ms * 1000);
        waited += tick_ms;
    }

    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
    return -1;
}

static int append_text(char *dst, size_t cap, size_t *off, const char *text) {
    if (!dst || !off || !text || cap == 0) return -1;
    size_t rem = cap - *off;
    if (rem == 0) return -1;
    int n = snprintf(dst + *off, rem, "%s", text);
    if (n < 0) return -1;
    if ((size_t)n >= rem) {
        *off = cap - 1;
        return -1;
    }
    *off += (size_t)n;
    return 0;
}

static const char *lookup_token(const hb_action_args *a, const char *token) {
    if (!a || !token) return "";
    if (!strcmp(token, "action")) return a->action ? a->action : "";
    if (!strcmp(token, "jail")) return a->jail ? a->jail : "";
    if (!strcmp(token, "filter")) return a->filter ? a->filter : "";
    if (!strcmp(token, "ip")) return a->ip ? a->ip : "";
    if (!strcmp(token, "proto")) return a->proto ? a->proto : "";
    return NULL;
}

static void expand_command_template(const char *tpl, const hb_action_args *a, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!tpl || !*tpl) return;

    size_t off = 0;
    for (size_t i = 0; tpl[i] != '\0'; i++) {
        if (tpl[i] != '{') {
            char ch[2] = {tpl[i], '\0'};
            if (append_text(out, out_cap, &off, ch) != 0) break;
            continue;
        }

        const char *end = strchr(tpl + i + 1, '}');
        if (!end) {
            if (append_text(out, out_cap, &off, tpl + i) != 0) break;
            break;
        }
        size_t tok_len = (size_t)(end - (tpl + i + 1));
        if (tok_len == 0 || tok_len > 31) {
            if (append_text(out, out_cap, &off, "{") != 0) break;
            continue;
        }

        char tok[32];
        memcpy(tok, tpl + i + 1, tok_len);
        tok[tok_len] = '\0';

        const char *rep = lookup_token(a, tok);
        if (!rep) {
            if (!strcmp(tok, "port")) {
                char p[16];
                snprintf(p, sizeof(p), "%d", a->port);
                rep = p;
                (void)append_text(out, out_cap, &off, rep);
            } else if (!strcmp(tok, "ttl")) {
                char t[16];
                snprintf(t, sizeof(t), "%d", a->ttl);
                rep = t;
                (void)append_text(out, out_cap, &off, rep);
            } else if (!strcmp(tok, "level")) {
                char l[16];
                snprintf(l, sizeof(l), "%d", a->level);
                rep = l;
                (void)append_text(out, out_cap, &off, rep);
            } else {
                if (append_text(out, out_cap, &off, "{") != 0) break;
                if (append_text(out, out_cap, &off, tok) != 0) break;
                if (append_text(out, out_cap, &off, "}") != 0) break;
            }
        } else {
            if (append_text(out, out_cap, &off, rep) != 0) break;
        }
        i = (size_t)(end - tpl);
    }
    out[out_cap - 1] = '\0';
}

static void *actions_worker(void *arg) {
    hb_actions_state *st = (hb_actions_state *)arg;
    if (!st) return NULL;

    for (;;) {
        hb_action_job job;
        memset(&job, 0, sizeof(job));

        pthread_mutex_lock(&st->q_mu);
        while (st->worker_running && st->jobs_len == 0) {
            pthread_cond_wait(&st->q_cv, &st->q_mu);
        }
        if (!st->worker_running && st->jobs_len == 0) {
            pthread_mutex_unlock(&st->q_mu);
            break;
        }

        uint16_t idx = st->jobs_head;
        job = st->jobs[idx];
        st->jobs_head = (uint16_t)((st->jobs_head + 1) % HB_MAX_ACTION_JOBS);
        st->jobs_len--;
        pthread_mutex_unlock(&st->q_mu);

        if (job.cmd[0]) {
            if (run_command_with_timeout(job.cmd, job.timeout_ms) != 0) {
                hb_log_error("action command failed action=%s", job.action);
            }
        }
    }

    return NULL;
}

static hb_actions_state *actions_state_build(void) {
    hb_actions_state *st = calloc(1, sizeof(*st));
    if (!st) return NULL;

    pthread_mutex_init(&st->q_mu, NULL);
    pthread_cond_init(&st->q_cv, NULL);
    st->worker_running = 1;

    hb_action_parse_ctx pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.st = st;
    pctx.default_timeout_ms = env_u32("HONEYBAN_ACTION_CMD_TIMEOUT_MS", 1000, 10, 30000);

    const char *dir = getenv("HONEYBAN_ACTIONS_DIR");
    if (!dir || !*dir) dir = "/etc/honeyban/actions.d";
    (void)load_actions_dir(&pctx, dir);

    if (pthread_create(&st->worker_thread, NULL, actions_worker, st) != 0) {
        pthread_mutex_destroy(&st->q_mu);
        pthread_cond_destroy(&st->q_cv);
        free(st);
        return NULL;
    }
    st->worker_started = 1;

    return st;
}

static void actions_state_free(hb_actions_state *st) {
    if (!st) return;

    pthread_mutex_lock(&st->q_mu);
    st->worker_running = 0;
    pthread_cond_signal(&st->q_cv);
    pthread_mutex_unlock(&st->q_mu);

    if (st->worker_started) pthread_join(st->worker_thread, NULL);

    pthread_mutex_destroy(&st->q_mu);
    pthread_cond_destroy(&st->q_cv);
    free(st);
}

static const hb_action_def *find_def(const hb_actions_state *st, const char *name) {
    if (!st || !name || !*name) return NULL;
    for (uint16_t i = 0; i < st->defs_len; i++) {
        if (!strcmp(st->defs[i].name, name)) return &st->defs[i];
    }
    return NULL;
}

static int enqueue_job(hb_actions_state *st, const hb_action_job *job) {
    if (!st || !job) return -1;
    int rc = 0;
    pthread_mutex_lock(&st->q_mu);
    if (st->jobs_len >= HB_MAX_ACTION_JOBS) {
        rc = -1;
    } else {
        uint16_t idx = (uint16_t)((st->jobs_head + st->jobs_len) % HB_MAX_ACTION_JOBS);
        st->jobs[idx] = *job;
        st->jobs_len++;
        pthread_cond_signal(&st->q_cv);
    }
    pthread_mutex_unlock(&st->q_mu);
    return rc;
}

static int apply_builtin(hb_ctx *ctx, hb_action_base base, const hb_action_args *a) {
    if (!ctx || !a || !a->ip || !*a->ip) return -1;
    const char *proto = (a->proto && !strcmp(a->proto, "udp")) ? "udp" : "tcp";
    int ttl = a->ttl < 0 ? 0 : a->ttl;
    int level = a->level <= 0 ? 3 : a->level;

    if (base == HB_ACTION_BASE_NONE) return 0;
    if (base == HB_ACTION_BASE_BAN_IP) return hb_ban_ip(ctx, a->ip, ttl, level);
    if (base == HB_ACTION_BASE_BAN_IP_PORT) {
        if (a->port > 0) return hb_ip_port_ban_add(ctx, a->ip, proto, a->port, ttl, level);
        return hb_ban_ip(ctx, a->ip, ttl, level);
    }
    if (base == HB_ACTION_BASE_BLOCK_PORT) {
        if (a->port > 0) return hb_port_block_add(ctx, proto, a->port, ttl);
        return hb_ban_ip(ctx, a->ip, ttl, level);
    }
    return hb_ban_ip(ctx, a->ip, ttl, level);
}

int hb_actions_load(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_actions_state *st = actions_state_build();
    if (!st) return -1;

    pthread_mutex_lock(&ctx->actions_mu);
    ctx->actions = st;
    pthread_mutex_unlock(&ctx->actions_mu);

    hb_log_info("actions loaded: %u", (unsigned)st->defs_len);
    return 0;
}

int hb_actions_reload(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_actions_state *next = actions_state_build();
    if (!next) return -1;

    pthread_mutex_lock(&ctx->actions_mu);
    hb_actions_state *prev = (hb_actions_state *)ctx->actions;
    ctx->actions = next;
    pthread_mutex_unlock(&ctx->actions_mu);

    if (prev) actions_state_free(prev);
    hb_log_info("actions reloaded: %u", (unsigned)next->defs_len);
    return 0;
}

void hb_actions_free(hb_ctx *ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&ctx->actions_mu);
    hb_actions_state *st = (hb_actions_state *)ctx->actions;
    ctx->actions = NULL;
    pthread_mutex_unlock(&ctx->actions_mu);
    if (st) actions_state_free(st);
}

int hb_actions_apply_ban(hb_ctx *ctx, const char *action_name, const char *jail_name, const char *filter_name, const char *ip_str,
                         const char *proto, int port, int ttl, int level) {
    if (!ctx || !ip_str || !*ip_str) return -1;
    if (!action_name || !*action_name) action_name = "banip";

    hb_action_args args;
    memset(&args, 0, sizeof(args));
    args.action = action_name;
    args.jail = jail_name ? jail_name : "";
    args.filter = filter_name ? filter_name : "";
    args.ip = ip_str;
    args.proto = proto ? proto : "tcp";
    args.port = port;
    args.ttl = ttl;
    args.level = level;

    hb_action_def def_copy;
    memset(&def_copy, 0, sizeof(def_copy));
    int has_def = 0;

    pthread_mutex_lock(&ctx->actions_mu);
    const hb_actions_state *st = (const hb_actions_state *)ctx->actions;
    if (st) {
        const hb_action_def *d = find_def(st, action_name);
        if (d) {
            def_copy = *d;
            has_def = 1;
        }
    }
    pthread_mutex_unlock(&ctx->actions_mu);

    hb_action_base base = HB_ACTION_BASE_UNKNOWN;
    if (has_def) {
        if (def_copy.enabled) base = def_copy.base;
        else base = parse_base(action_name);
    } else {
        base = parse_base(action_name);
    }
    if (base == HB_ACTION_BASE_UNKNOWN) base = fallback_base(action_name);

    int rc = apply_builtin(ctx, base, &args);

    if (has_def && def_copy.enabled && def_copy.ban_cmd[0]) {
        hb_action_job job;
        memset(&job, 0, sizeof(job));
        strncpy(job.action, action_name, sizeof(job.action) - 1);
        job.timeout_ms = def_copy.timeout_ms ? def_copy.timeout_ms : 1000;
        expand_command_template(def_copy.ban_cmd, &args, job.cmd, sizeof(job.cmd));

        pthread_mutex_lock(&ctx->actions_mu);
        hb_actions_state *st = (hb_actions_state *)ctx->actions;
        if (st && enqueue_job(st, &job) != 0) hb_log_error("action queue full, dropped action=%s", action_name);
        pthread_mutex_unlock(&ctx->actions_mu);
    }

    return rc;
}
