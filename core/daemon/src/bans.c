// SPDX-License-Identifier: MIT

#include "bans.h"
#include "log.h"
#include "timeutil.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

static int ip_version(const char *ip) {
    if (!ip || !*ip) return 0;
    return strchr(ip, ':') ? 6 : 4;
}

static int parse_ipv4(const char *ip, uint32_t *out) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    *out = a.s_addr;
    return 0;
}

static int parse_ipv6(const char *ip, hb_ip_ban_key_v6 *out) {
    struct in6_addr a;
    if (inet_pton(AF_INET6, ip, &a) != 1) return -1;
    memcpy(out->ip, a.s6_addr, 16);
    return 0;
}

static int proto_from_str(const char *s) {
    if (!s) return -1;
    if (!strcmp(s, "tcp")) return IPPROTO_TCP;
    if (!strcmp(s, "udp")) return IPPROTO_UDP;
    return -1;
}

static hb_ban_value ban_value(int ttl, int level) {
    hb_ban_value v;
    memset(&v, 0, sizeof(v));
    v.ban_time = hb_mono_sec();
    v.ttl = ttl > 0 ? (uint32_t)ttl : 0;
    if (level < 0) level = 0;
    if (level > 5) level = 5;
    v.ban_level = (uint32_t)level;
    return v;
}

int hb_ban_ip(hb_ctx *ctx, const char *ip_str, int ttl, int level) {
    if (!ctx || !ip_str) return -1;
    int ver = ip_version(ip_str);
    hb_ban_value v = ban_value(ttl, level);

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_ban_key_v6 k6;
        if (parse_ipv6(ip_str, &k6) == 0) {
            ret = bpf_map_update_elem(ctx->map_fd_ip_ban_v6, &k6, &v, BPF_ANY);
        }
    } else {
        hb_ip_ban_key_v4 k4;
        memset(&k4, 0, sizeof(k4));
        if (parse_ipv4(ip_str, &k4.ip) == 0) {
            ret = bpf_map_update_elem(ctx->map_fd_ip_ban_v4, &k4, &v, BPF_ANY);
        }
    }
    if (ret == 0) ctx->total_bans++;
    else ctx->total_errors++;
    pthread_mutex_unlock(&ctx->lock);

    if (ret == 0) hb_log_info("ban ip=%s ttl=%d level=%d", ip_str, ttl, level);
    else hb_log_error("ban failed ip=%s err=%s", ip_str, strerror(errno));
    return ret;
}

int hb_unban_ip(hb_ctx *ctx, const char *ip_str) {
    if (!ctx || !ip_str) return -1;
    int ver = ip_version(ip_str);

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_ban_key_v6 k6;
        if (parse_ipv6(ip_str, &k6) == 0) {
            ret = bpf_map_delete_elem(ctx->map_fd_ip_ban_v6, &k6);
        }
    } else {
        hb_ip_ban_key_v4 k4;
        memset(&k4, 0, sizeof(k4));
        if (parse_ipv4(ip_str, &k4.ip) == 0) {
            ret = bpf_map_delete_elem(ctx->map_fd_ip_ban_v4, &k4);
        }
    }
    if (ret == 0) ctx->total_unbans++;
    pthread_mutex_unlock(&ctx->lock);

    if (ret == 0) hb_log_info("unban ip=%s", ip_str);
    return ret;
}

int hb_whitelist_add(hb_ctx *ctx, const char *ip_str) {
    if (!ctx || !ip_str) return -1;
    int ver = ip_version(ip_str);
    uint8_t one = 1;

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_ban_key_v6 k6;
        if (parse_ipv6(ip_str, &k6) == 0) {
            ret = bpf_map_update_elem(ctx->map_fd_whitelist_v6, &k6, &one, BPF_ANY);
        }
    } else {
        uint32_t ip;
        if (parse_ipv4(ip_str, &ip) == 0) {
            ret = bpf_map_update_elem(ctx->map_fd_whitelist_v4, &ip, &one, BPF_ANY);
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

int hb_whitelist_del(hb_ctx *ctx, const char *ip_str) {
    if (!ctx || !ip_str) return -1;
    int ver = ip_version(ip_str);

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_ban_key_v6 k6;
        if (parse_ipv6(ip_str, &k6) == 0) {
            ret = bpf_map_delete_elem(ctx->map_fd_whitelist_v6, &k6);
        }
    } else {
        uint32_t ip;
        if (parse_ipv4(ip_str, &ip) == 0) {
            ret = bpf_map_delete_elem(ctx->map_fd_whitelist_v4, &ip);
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

int hb_port_block_add(hb_ctx *ctx, const char *proto_str, int port, int ttl) {
    if (!ctx || !proto_str) return -1;
    int proto = proto_from_str(proto_str);
    if (proto < 0) return -1;
    if (port <= 0 || port > 65535) return -1;
    hb_port_key k;
    k.proto = (uint8_t)proto;
    k.pad = 0;
    k.dport = (uint16_t)port;
    hb_ban_value v = ban_value(ttl, 0);

    pthread_mutex_lock(&ctx->lock);
    int ret = bpf_map_update_elem(ctx->map_fd_port_block, &k, &v, BPF_ANY);
    if (ret == 0) ctx->total_port_blocks++;
    else ctx->total_errors++;
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

int hb_port_block_del(hb_ctx *ctx, const char *proto_str, int port) {
    if (!ctx || !proto_str) return -1;
    int proto = proto_from_str(proto_str);
    if (proto < 0) return -1;
    if (port <= 0 || port > 65535) return -1;
    hb_port_key k;
    k.proto = (uint8_t)proto;
    k.pad = 0;
    k.dport = (uint16_t)port;
    pthread_mutex_lock(&ctx->lock);
    int ret = bpf_map_delete_elem(ctx->map_fd_port_block, &k);
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

int hb_ip_port_ban_add(hb_ctx *ctx, const char *ip_str, const char *proto_str, int port, int ttl, int level) {
    if (!ctx || !ip_str || !proto_str) return -1;
    int proto = proto_from_str(proto_str);
    if (proto < 0) return -1;
    if (port <= 0 || port > 65535) return -1;
    hb_ban_value v = ban_value(ttl, level);
    int ver = ip_version(ip_str);

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_port_key_v6 k;
        memset(&k, 0, sizeof(k));
        if (parse_ipv6(ip_str, &k.ip6) == 0) {
            k.p.proto = (uint8_t)proto;
            k.p.pad = 0;
            k.p.dport = (uint16_t)port;
            ret = bpf_map_update_elem(ctx->map_fd_ip_port_v6, &k, &v, BPF_ANY);
        }
    } else {
        hb_ip_port_key_v4 k;
        memset(&k, 0, sizeof(k));
        if (parse_ipv4(ip_str, &k.ip) == 0) {
            k.p.proto = (uint8_t)proto;
            k.p.pad = 0;
            k.p.dport = (uint16_t)port;
            ret = bpf_map_update_elem(ctx->map_fd_ip_port_v4, &k, &v, BPF_ANY);
        }
    }
    if (ret == 0) ctx->total_bans++;
    else ctx->total_errors++;
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

int hb_ip_port_ban_del(hb_ctx *ctx, const char *ip_str, const char *proto_str, int port) {
    if (!ctx || !ip_str || !proto_str) return -1;
    int proto = proto_from_str(proto_str);
    if (proto < 0) return -1;
    if (port <= 0 || port > 65535) return -1;
    int ver = ip_version(ip_str);

    pthread_mutex_lock(&ctx->lock);
    int ret = -1;
    if (ver == 6) {
        hb_ip_port_key_v6 k;
        memset(&k, 0, sizeof(k));
        if (parse_ipv6(ip_str, &k.ip6) == 0) {
            k.p.proto = (uint8_t)proto;
            k.p.pad = 0;
            k.p.dport = (uint16_t)port;
            ret = bpf_map_delete_elem(ctx->map_fd_ip_port_v6, &k);
        }
    } else {
        hb_ip_port_key_v4 k;
        memset(&k, 0, sizeof(k));
        if (parse_ipv4(ip_str, &k.ip) == 0) {
            k.p.proto = (uint8_t)proto;
            k.p.pad = 0;
            k.p.dport = (uint16_t)port;
            ret = bpf_map_delete_elem(ctx->map_fd_ip_port_v4, &k);
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

