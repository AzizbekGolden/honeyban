// SPDX-License-Identifier: MIT

#include "config.h"
#include "log.h"

#include <bpf/bpf.h>
#include <stdlib.h>
#include <string.h>

int hb_config_get(hb_ctx *ctx, hb_config *out) {
    if (!ctx || !out || ctx->map_fd_control <= 0) return -1;
    uint32_t idx = 0;
    return bpf_map_lookup_elem(ctx->map_fd_control, &idx, out);
}

int hb_config_set(hb_ctx *ctx, const hb_config *cfg) {
    if (!ctx || !cfg || ctx->map_fd_control <= 0) return -1;
    uint32_t idx = 0;
    return bpf_map_update_elem(ctx->map_fd_control, &idx, cfg, BPF_ANY);
}

int hb_config_init_defaults(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_config cfg;
    if (hb_config_get(ctx, &cfg) == 0 && cfg.flags != 0) {
        ctx->cfg = cfg;
        return 0;
    }

    memset(&cfg, 0, sizeof(cfg));

    cfg.flags = 1u;          // XDP enabled
    cfg.flags |= (1u << 1);  // synflood detector enabled
    cfg.flags |= (1u << 2);  // portscan detector enabled
    cfg.flags |= (1u << 3);  // ssh detector enabled
    cfg.flags |= (1u << 4);  // telemetry enabled (for userspace detectors)
    cfg.flags |= (1u << 5);  // journal filters enabled (systemd-journald)

    cfg.syn_threshold = 200;
    cfg.syn_window_sec = 1;

    cfg.portscan_threshold = 20;
    cfg.portscan_window_sec = 10;

    cfg.ssh_threshold = 8;     // failed attempts (journald) or connections fallback
    cfg.ssh_window_sec = 120;  // seconds

    cfg.autoban_level = 3;
    cfg.autoban_ttl = 600;

    if (hb_config_set(ctx, &cfg) != 0) {
        hb_log_error("failed to initialize default config");
        return -1;
    }

    ctx->cfg = cfg;
    hb_log_info("default config initialized");
    return 0;
}

int hb_config_apply_profile(hb_ctx *ctx) {
    if (!ctx) return -1;
    const char *profile = getenv("HONEYBAN_PROFILE");
    if (!profile || !*profile || !strcmp(profile, "custom")) {
        return 0;
    }

    hb_config cfg;
    if (hb_config_get(ctx, &cfg) != 0) return -1;

    if (!strcmp(profile, "fast")) {
        // Max speed: XDP only, no telemetry/detectors.
        cfg.flags = 1u;
    } else if (!strcmp(profile, "accurate")) {
        // Accurate detection with conservative thresholds.
        cfg.flags = 1u | (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) | (1u << 5);
        cfg.syn_threshold = 300;
        cfg.syn_window_sec = 1;
        cfg.portscan_threshold = 25;
        cfg.portscan_window_sec = 10;
        cfg.ssh_threshold = 8;
        cfg.ssh_window_sec = 120;
        cfg.autoban_level = 3;
        cfg.autoban_ttl = 900;
    } else {
        return 0;
    }

    if (hb_config_set(ctx, &cfg) != 0) return -1;
    ctx->cfg = cfg;
    hb_log_info("profile applied: %s", profile);
    return 0;
}

static int parse_on_off(const char *v, int *out) {
    if (!v || !*v) return 0;
    if (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "on") || !strcmp(v, "yes")) {
        *out = 1;
        return 1;
    }
    if (!strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "off") || !strcmp(v, "no")) {
        *out = 0;
        return 1;
    }
    return 0;
}

static int parse_u32(const char *v, uint32_t *out) {
    if (!v || !*v) return 0;
    char *end = NULL;
    unsigned long val = strtoul(v, &end, 10);
    if (!end || *end != '\0') return 0;
    *out = (uint32_t)val;
    return 1;
}

int hb_config_apply_env(hb_ctx *ctx) {
    if (!ctx) return -1;
    hb_config cfg;
    if (hb_config_get(ctx, &cfg) != 0) return -1;

    int v = 0;
    const char *s;

    s = getenv("HONEYBAN_XDP_ENABLED");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= 1u;
        else cfg.flags &= ~1u;
    }

    s = getenv("HONEYBAN_TELEMETRY");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= (1u << 4);
        else cfg.flags &= ~(1u << 4);
    }

    s = getenv("HONEYBAN_SYN_ENABLED");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= (1u << 1);
        else cfg.flags &= ~(1u << 1);
    }

    s = getenv("HONEYBAN_PORTSCAN_ENABLED");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= (1u << 2);
        else cfg.flags &= ~(1u << 2);
    }

    s = getenv("HONEYBAN_SSH_ENABLED");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= (1u << 3);
        else cfg.flags &= ~(1u << 3);
    }

    s = getenv("HONEYBAN_JOURNAL_ENABLED");
    if (parse_on_off(s, &v)) {
        if (v) cfg.flags |= (1u << 5);
        else cfg.flags &= ~(1u << 5);
    }

    uint32_t u;
    s = getenv("HONEYBAN_SYN_THRESHOLD");
    if (parse_u32(s, &u)) cfg.syn_threshold = u;
    s = getenv("HONEYBAN_SYN_WINDOW_SEC");
    if (parse_u32(s, &u)) cfg.syn_window_sec = u;
    s = getenv("HONEYBAN_PORTSCAN_THRESHOLD");
    if (parse_u32(s, &u)) cfg.portscan_threshold = u;
    s = getenv("HONEYBAN_PORTSCAN_WINDOW_SEC");
    if (parse_u32(s, &u)) cfg.portscan_window_sec = u;
    s = getenv("HONEYBAN_SSH_THRESHOLD");
    if (parse_u32(s, &u)) cfg.ssh_threshold = u;
    s = getenv("HONEYBAN_SSH_WINDOW_SEC");
    if (parse_u32(s, &u)) cfg.ssh_window_sec = u;
    s = getenv("HONEYBAN_AUTOBAN_LEVEL");
    if (parse_u32(s, &u)) cfg.autoban_level = u;
    s = getenv("HONEYBAN_AUTOBAN_TTL");
    if (parse_u32(s, &u)) cfg.autoban_ttl = u;

    if (hb_config_set(ctx, &cfg) != 0) return -1;
    ctx->cfg = cfg;
    hb_log_info("config loaded from environment");
    return 0;
}
