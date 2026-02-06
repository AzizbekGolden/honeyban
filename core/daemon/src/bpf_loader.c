// SPDX-License-Identifier: MIT

#include "bpf_loader.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

static uint32_t parse_xdp_flags(void) {
    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    const char *mode = getenv("HONEYBAN_XDP_MODE");
    if (mode && *mode) {
        flags &= ~(XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE | XDP_FLAGS_HW_MODE);
        if (!strcmp(mode, "driver") || !strcmp(mode, "native")) {
            flags |= XDP_FLAGS_DRV_MODE;
        } else if (!strcmp(mode, "generic") || !strcmp(mode, "skb")) {
            flags |= XDP_FLAGS_SKB_MODE;
        } else if (!strcmp(mode, "hw")) {
            flags |= XDP_FLAGS_HW_MODE;
        }
    }

    const char *extra = getenv("HONEYBAN_XDP_FLAGS");
    if (extra && *extra) {
        char *end = NULL;
        unsigned long v = strtoul(extra, &end, 0);
        if (end && *end == '\0') {
            flags |= (uint32_t)v;
        }
    }
    return flags;
}

static int find_maps(hb_ctx *ctx) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, ctx->obj) {
        const char *name = bpf_map__name(map);
        int fd = bpf_map__fd(map);

        if (!strcmp(name, "ip_ban_map")) ctx->map_fd_ip_ban_v4 = fd;
        else if (!strcmp(name, "ip_ban_map_v6")) ctx->map_fd_ip_ban_v6 = fd;
        else if (!strcmp(name, "whitelist_map")) ctx->map_fd_whitelist_v4 = fd;
        else if (!strcmp(name, "whitelist_map_v6")) ctx->map_fd_whitelist_v6 = fd;
        else if (!strcmp(name, "control_map")) ctx->map_fd_control = fd;
        else if (!strcmp(name, "port_block_map")) ctx->map_fd_port_block = fd;
        else if (!strcmp(name, "ip_port_ban_map")) ctx->map_fd_ip_port_v4 = fd;
        else if (!strcmp(name, "ip_port_ban_map_v6")) ctx->map_fd_ip_port_v6 = fd;
        else if (!strcmp(name, "rb_telemetry")) ctx->map_fd_rb = fd;
    }

    if (ctx->map_fd_ip_ban_v4 <= 0 || ctx->map_fd_ip_ban_v6 <= 0 || ctx->map_fd_control <= 0) {
        hb_log_error("missing required BPF maps (ip_ban_map, ip_ban_map_v6, control_map)");
        return -1;
    }
    if (ctx->map_fd_port_block <= 0 || ctx->map_fd_ip_port_v4 <= 0 || ctx->map_fd_ip_port_v6 <= 0) {
        hb_log_error("missing required BPF maps (port_block_map, ip_port_ban_map, ip_port_ban_map_v6)");
        return -1;
    }
    if (ctx->map_fd_rb <= 0) {
        hb_log_error("missing telemetry ringbuf map (rb_telemetry)");
        return -1;
    }
    return 0;
}

int hb_bpf_load_and_attach(hb_ctx *ctx, const char *iface, const char *bpf_obj_path) {
    if (!ctx || !iface || !*iface) return -1;

    ctx->obj = bpf_object__open(bpf_obj_path);
    if (libbpf_get_error(ctx->obj)) {
        hb_log_error("bpf_object__open failed: %s", strerror(errno));
        ctx->obj = NULL;
        return -1;
    }
    if (bpf_object__load(ctx->obj)) {
        hb_log_error("bpf_object__load failed: %s", strerror(errno));
        return -1;
    }

    ctx->prog = bpf_object__find_program_by_name(ctx->obj, "xdp_ddos_filter");
    if (!ctx->prog) {
        hb_log_error("XDP program 'xdp_ddos_filter' not found");
        return -1;
    }
    ctx->prog_fd = bpf_program__fd(ctx->prog);
    if (ctx->prog_fd < 0) {
        hb_log_error("bpf_program__fd failed");
        return -1;
    }

    if (find_maps(ctx) < 0) return -1;

    ctx->ifindex = if_nametoindex(iface);
    if (!ctx->ifindex) {
        hb_log_error("interface not found: %s", iface);
        return -1;
    }
    strncpy(ctx->iface, iface, IF_NAMESIZE - 1);

    ctx->xdp_flags = parse_xdp_flags();
    if (bpf_xdp_attach(ctx->ifindex, ctx->prog_fd, ctx->xdp_flags, NULL) < 0) {
        hb_log_error("bpf_xdp_attach failed: %s", strerror(errno));
        return -1;
    }
    hb_log_info("XDP attached: iface=%s ifindex=%d", ctx->iface, ctx->ifindex);
    return 0;
}

void hb_bpf_detach_and_close(hb_ctx *ctx) {
    if (!ctx) return;

    if (ctx->ifindex > 0) {
        (void)bpf_xdp_detach(ctx->ifindex, ctx->xdp_flags, NULL);
        hb_log_info("XDP detached: iface=%s", ctx->iface);
        ctx->ifindex = 0;
    }

    if (ctx->obj) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
    }
}
