// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define XDP_PASS 2
#define XDP_DROP 1

#define MAX_IP_ENTRIES 100000
#define MAX_WHITELIST 10000

#define TELEMETRY_MAX_BYTES (1024 * 1024) // 1 MiB ringbuf

#define TCP_FLAG_SYN 0x02

struct ip_ban_key {
    __u32 ip;
    __u32 padding[3];
};

struct ip_ban_key_v6 {
    __u8 ip[16];
};

// Time base: monotonic seconds since boot (must match userspace CLOCK_MONOTONIC).
struct ip_ban_value {
    __u64 ban_time;
    __u32 ban_level;
    __u32 ttl;
};

struct port_key {
    __u8 proto;  // IPPROTO_*
    __u8 pad;
    __u16 dport; // host order
};

struct ip_port_key_v4 {
    __u32 ip;          // network order
    struct port_key p; // host order
    __u32 pad;
};

struct ip_port_key_v6 {
    struct ip_ban_key_v6 ip6;
    struct port_key p;
};

struct telemetry_event {
    __u64 timestamp;
    __u8 ip_version; // 4 or 6
    __u8 action;     // 0 pass, 1 drop
    __u8 protocol;
    __u8 tcp_flags;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8 ban_level;
    __u8 reason;   // 0 none, 1 ip_ban, 2 ip_port_ban, 3 port_block
    __u8 src_ip6[16];
};

struct honeyban_config {
    // Bit 0: XDP enabled
    // Bit 1-3: detector enable flags (userspace and/or kernel fast-path)
    // Bit 4: telemetry enabled
    // Bit 5: reserved for userspace (journal filters)
    __u32 flags;

    // Userspace tuning (and kernel-side detectors when enabled).
    __u32 syn_threshold;
    __u32 syn_window_sec;
    __u32 portscan_threshold;
    __u32 portscan_window_sec;
    __u32 ssh_threshold;
    __u32 ssh_window_sec;
    __u32 autoban_level;
    __u32 autoban_ttl;
    __u32 reserved0;
};

struct rate_state {
    __u64 window_start;
    __u32 count;
    __u32 pad;
};

struct portscan_state {
    __u64 window_start;
    __u64 bits;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_state);
} syn_rate_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct ip_ban_key_v6);
    __type(value, struct rate_state);
} syn_rate_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct portscan_state);
} portscan_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct ip_ban_key_v6);
    __type(value, struct portscan_state);
} portscan_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, struct ip_ban_key);
    __type(value, struct ip_ban_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_ban_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, struct ip_ban_key_v6);
    __type(value, struct ip_ban_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_ban_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, struct ip_ban_key_v6);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct port_key);
    __type(value, struct ip_ban_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct ip_port_key_v4);
    __type(value, struct ip_ban_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_port_ban_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct ip_port_key_v6);
    __type(value, struct ip_ban_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_port_ban_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, TELEMETRY_MAX_BYTES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_telemetry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct honeyban_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} control_map SEC(".maps");

static __always_inline __u64 now_sec(void) {
    return bpf_ktime_get_ns() / 1000000000ULL;
}

static __always_inline int telemetry_enabled(const struct honeyban_config *cfg) {
    return cfg && (cfg->flags & (1u << 4));
}

static __always_inline int is_whitelisted_v4(__u32 ip) {
    return bpf_map_lookup_elem(&whitelist_map, &ip) != NULL;
}

static __always_inline int is_whitelisted_v6(const struct ip_ban_key_v6 *ip6) {
    return bpf_map_lookup_elem(&whitelist_map_v6, ip6) != NULL;
}

static __always_inline int expired(const struct ip_ban_value *v, __u64 now) {
    return v && v->ttl > 0 && now > v->ban_time + v->ttl;
}

static __always_inline __u32 clamp_u32(__u32 v, __u32 minv, __u32 maxv) {
    if (v < minv) return minv;
    if (v > maxv) return maxv;
    return v;
}

static __always_inline __u32 cfg_u32(const struct honeyban_config *cfg, __u32 v, __u32 defv, __u32 minv, __u32 maxv) {
    if (!cfg) return defv;
    if (v == 0) v = defv;
    return clamp_u32(v, minv, maxv);
}

static __always_inline int syn_no_ack(__u8 tcp_flags) {
    return (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);
}

static __always_inline void autoban_v4(__u32 src_ip, const struct honeyban_config *cfg, __u32 ttl, __u32 level) {
    struct ip_ban_key k = {.ip = src_ip, .padding = {0, 0, 0}};
    struct ip_ban_value v = {.ban_time = now_sec(), .ban_level = level, .ttl = ttl};
    (void)bpf_map_update_elem(&ip_ban_map, &k, &v, BPF_ANY);
}

static __always_inline void autoban_v6(const struct ip_ban_key_v6 *src_ip6, const struct honeyban_config *cfg, __u32 ttl,
                                      __u32 level) {
    if (!src_ip6) return;
    struct ip_ban_value v = {.ban_time = now_sec(), .ban_level = level, .ttl = ttl};
    (void)bpf_map_update_elem(&ip_ban_map_v6, src_ip6, &v, BPF_ANY);
}

static __always_inline int run_syn_detector_v4(__u32 src_ip, __u8 tcp_flags, const struct honeyban_config *cfg, __u8 *out_level) {
    if (!cfg) return 0;
    if (!(cfg->flags & (1u << 1))) return 0;
    if (!syn_no_ack(tcp_flags)) return 0;

    __u32 win = cfg_u32(cfg, cfg->syn_window_sec, 1, 1, 60);
    __u32 thr = cfg_u32(cfg, cfg->syn_threshold, 200, 1, 1000000);

    __u64 now = now_sec();
    struct rate_state *s = bpf_map_lookup_elem(&syn_rate_v4, &src_ip);
    if (!s) {
        struct rate_state init = {.window_start = now, .count = 1, .pad = 0};
        (void)bpf_map_update_elem(&syn_rate_v4, &src_ip, &init, BPF_ANY);
        return 0;
    }
    if (now - s->window_start >= win) {
        s->window_start = now;
        s->count = 1;
        return 0;
    }
    s->count++;
    if (s->count < thr) return 0;

    __u32 ttl = cfg_u32(cfg, cfg->autoban_ttl, 300, 0, 86400);
    __u32 lvl = cfg_u32(cfg, cfg->autoban_level, 3, 0, 5);
    if (out_level) *out_level = (__u8)lvl;
    autoban_v4(src_ip, cfg, ttl, lvl);
    s->window_start = now;
    s->count = 0;
    return 1;
}

static __always_inline int run_syn_detector_v6(const struct ip_ban_key_v6 *src_ip6, __u8 tcp_flags, const struct honeyban_config *cfg,
                                               __u8 *out_level) {
    if (!cfg || !src_ip6) return 0;
    if (!(cfg->flags & (1u << 1))) return 0;
    if (!syn_no_ack(tcp_flags)) return 0;

    __u32 win = cfg_u32(cfg, cfg->syn_window_sec, 1, 1, 60);
    __u32 thr = cfg_u32(cfg, cfg->syn_threshold, 200, 1, 1000000);

    __u64 now = now_sec();
    struct rate_state *s = bpf_map_lookup_elem(&syn_rate_v6, src_ip6);
    if (!s) {
        struct rate_state init = {.window_start = now, .count = 1, .pad = 0};
        (void)bpf_map_update_elem(&syn_rate_v6, src_ip6, &init, BPF_ANY);
        return 0;
    }
    if (now - s->window_start >= win) {
        s->window_start = now;
        s->count = 1;
        return 0;
    }
    s->count++;
    if (s->count < thr) return 0;

    __u32 ttl = cfg_u32(cfg, cfg->autoban_ttl, 300, 0, 86400);
    __u32 lvl = cfg_u32(cfg, cfg->autoban_level, 3, 0, 5);
    if (out_level) *out_level = (__u8)lvl;
    autoban_v6(src_ip6, cfg, ttl, lvl);
    s->window_start = now;
    s->count = 0;
    return 1;
}

static __always_inline __u64 port_hash_bit(__u16 dport) {
    __u32 h = (__u32)dport * 2654435761u;
    __u32 bit = (h >> 26) & 63u;
    return 1ULL << bit;
}

static __always_inline int run_portscan_v4(__u32 src_ip, __u16 dport, __u8 tcp_flags, const struct honeyban_config *cfg, __u8 *out_level) {
    if (!cfg) return 0;
    if (!(cfg->flags & (1u << 2))) return 0;
    if (!syn_no_ack(tcp_flags)) return 0;
    if (dport == 0) return 0;

    __u32 win = cfg_u32(cfg, cfg->portscan_window_sec, 10, 1, 300);
    __u32 thr = cfg_u32(cfg, cfg->portscan_threshold, 20, 1, 64);

    __u64 now = now_sec();
    struct portscan_state *s = bpf_map_lookup_elem(&portscan_v4, &src_ip);
    if (!s) {
        struct portscan_state init = {.window_start = now, .bits = port_hash_bit(dport)};
        (void)bpf_map_update_elem(&portscan_v4, &src_ip, &init, BPF_ANY);
        return 0;
    }
    if (now - s->window_start >= win) {
        s->window_start = now;
        s->bits = 0;
    }
    s->bits |= port_hash_bit(dport);
    __u32 uniq = (__u32)__builtin_popcountll(s->bits);
    if (uniq < thr) return 0;

    __u32 ttl = cfg_u32(cfg, cfg->autoban_ttl, 600, 0, 86400);
    __u32 lvl = cfg_u32(cfg, cfg->autoban_level, 3, 0, 5);
    if (out_level) *out_level = (__u8)lvl;
    autoban_v4(src_ip, cfg, ttl, lvl);
    s->window_start = now;
    s->bits = 0;
    return 1;
}

static __always_inline int run_portscan_v6(const struct ip_ban_key_v6 *src_ip6, __u16 dport, __u8 tcp_flags, const struct honeyban_config *cfg,
                                           __u8 *out_level) {
    if (!cfg || !src_ip6) return 0;
    if (!(cfg->flags & (1u << 2))) return 0;
    if (!syn_no_ack(tcp_flags)) return 0;
    if (dport == 0) return 0;

    __u32 win = cfg_u32(cfg, cfg->portscan_window_sec, 10, 1, 300);
    __u32 thr = cfg_u32(cfg, cfg->portscan_threshold, 20, 1, 64);

    __u64 now = now_sec();
    struct portscan_state *s = bpf_map_lookup_elem(&portscan_v6, src_ip6);
    if (!s) {
        struct portscan_state init = {.window_start = now, .bits = port_hash_bit(dport)};
        (void)bpf_map_update_elem(&portscan_v6, src_ip6, &init, BPF_ANY);
        return 0;
    }
    if (now - s->window_start >= win) {
        s->window_start = now;
        s->bits = 0;
    }
    s->bits |= port_hash_bit(dport);
    __u32 uniq = (__u32)__builtin_popcountll(s->bits);
    if (uniq < thr) return 0;

    __u32 ttl = cfg_u32(cfg, cfg->autoban_ttl, 600, 0, 86400);
    __u32 lvl = cfg_u32(cfg, cfg->autoban_level, 3, 0, 5);
    if (out_level) *out_level = (__u8)lvl;
    autoban_v6(src_ip6, cfg, ttl, lvl);
    s->window_start = now;
    s->bits = 0;
    return 1;
}

static __always_inline int check_ban_v4(__u32 ip, __u8 *out_level) {
    struct ip_ban_key k = {.ip = ip, .padding = {0, 0, 0}};
    struct ip_ban_value *v = bpf_map_lookup_elem(&ip_ban_map, &k);
    if (!v) return 0;
    __u64 now = now_sec();
    if (expired(v, now)) {
        bpf_map_delete_elem(&ip_ban_map, &k);
        return 0;
    }
    *out_level = (__u8)v->ban_level;
    return 1;
}

static __always_inline int check_ban_v6(const struct ip_ban_key_v6 *ip6, __u8 *out_level) {
    struct ip_ban_value *v = bpf_map_lookup_elem(&ip_ban_map_v6, ip6);
    if (!v) return 0;
    __u64 now = now_sec();
    if (expired(v, now)) {
        bpf_map_delete_elem(&ip_ban_map_v6, ip6);
        return 0;
    }
    *out_level = (__u8)v->ban_level;
    return 1;
}

static __always_inline int check_port_block(__u8 proto, __u16 dport) {
    struct port_key k = {.proto = proto, .pad = 0, .dport = dport};
    struct ip_ban_value *v = bpf_map_lookup_elem(&port_block_map, &k);
    if (!v) return 0;
    __u64 now = now_sec();
    if (expired(v, now)) {
        bpf_map_delete_elem(&port_block_map, &k);
        return 0;
    }
    return 1;
}

static __always_inline int check_ip_port_v4(__u32 ip, __u8 proto, __u16 dport, __u8 *out_level) {
    struct ip_port_key_v4 k = {.ip = ip, .p = {.proto = proto, .pad = 0, .dport = dport}, .pad = 0};
    struct ip_ban_value *v = bpf_map_lookup_elem(&ip_port_ban_map, &k);
    if (!v) return 0;
    __u64 now = now_sec();
    if (expired(v, now)) {
        bpf_map_delete_elem(&ip_port_ban_map, &k);
        return 0;
    }
    *out_level = (__u8)v->ban_level;
    return 1;
}

static __always_inline int check_ip_port_v6(const struct ip_ban_key_v6 *ip6, __u8 proto, __u16 dport, __u8 *out_level) {
    struct ip_port_key_v6 k;
    __builtin_memcpy(&k.ip6, ip6, sizeof(*ip6));
    k.p.proto = proto;
    k.p.pad = 0;
    k.p.dport = dport;
    struct ip_ban_value *v = bpf_map_lookup_elem(&ip_port_ban_map_v6, &k);
    if (!v) return 0;
    __u64 now = now_sec();
    if (expired(v, now)) {
        bpf_map_delete_elem(&ip_port_ban_map_v6, &k);
        return 0;
    }
    *out_level = (__u8)v->ban_level;
    return 1;
}

static __always_inline void emit_telemetry(__u8 ip_version, const void *src_ip, __u16 sport, __u16 dport,
                                          __u16 pkt_len, __u8 proto, __u8 tcp_flags, __u8 action,
                                          __u8 ban_level, __u8 reason) {
    struct telemetry_event *e = bpf_ringbuf_reserve(&rb_telemetry, sizeof(*e), 0);
    if (!e) return;
    e->timestamp = now_sec();
    e->ip_version = ip_version;
    e->action = action;
    e->protocol = proto;
    e->tcp_flags = tcp_flags;
    e->src_port = sport;
    e->dst_port = dport;
    e->pkt_len = pkt_len;
    e->ban_level = ban_level;
    e->reason = reason;
    __builtin_memset(e->src_ip6, 0, sizeof(e->src_ip6));
    if (ip_version == 4) {
        __builtin_memcpy(e->src_ip6, src_ip, 4);
    } else {
        __builtin_memcpy(e->src_ip6, src_ip, 16);
    }
    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u16 pkt_len = (__u16)(data_end - data);

    __u32 idx = 0;
    struct honeyban_config *cfg = bpf_map_lookup_elem(&control_map, &idx);
    if (cfg && !(cfg->flags & 0x1)) return XDP_PASS;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        __u32 src_ip = iph->saddr;
        __u8 proto = iph->protocol;

        __u16 sport = 0, dport = 0;
        __u8 tcp_flags = 0;
        if (proto == IPPROTO_TCP) {
            __u32 ihl = (__u32)iph->ihl * 4;
            if (ihl < sizeof(*iph)) return XDP_PASS;
            struct tcphdr *tcph = (void *)((__u8 *)iph + ihl);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;
            sport = bpf_ntohs(tcph->source);
            dport = bpf_ntohs(tcph->dest);
            tcp_flags = ((__u8 *)tcph)[13];
        } else if (proto == IPPROTO_UDP) {
            __u32 ihl = (__u32)iph->ihl * 4;
            if (ihl < sizeof(*iph)) return XDP_PASS;
            struct udphdr *udph = (void *)((__u8 *)iph + ihl);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;
            sport = bpf_ntohs(udph->source);
            dport = bpf_ntohs(udph->dest);
        }

        if (is_whitelisted_v4(src_ip)) return XDP_PASS;

        __u8 ban_level = 0;
        if (check_ban_v4(src_ip, &ban_level)) {
            if (telemetry_enabled(cfg)) emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 1, ban_level, 1);
            return XDP_DROP;
        }

        if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
            if (check_ip_port_v4(src_ip, proto, dport, &ban_level)) {
                if (telemetry_enabled(cfg)) emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 1, ban_level, 2);
                return XDP_DROP;
            }
            if (check_port_block(proto, dport)) {
                if (telemetry_enabled(cfg)) emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 1, 0, 3);
                return XDP_DROP;
            }
        }

        if (proto == IPPROTO_TCP) {
            __u8 auto_lvl = 0;
            if (run_syn_detector_v4(src_ip, tcp_flags, cfg, &auto_lvl)) {
                if (telemetry_enabled(cfg)) emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 1, auto_lvl, 4);
                return XDP_DROP;
            }
            if (run_portscan_v4(src_ip, dport, tcp_flags, cfg, &auto_lvl)) {
                if (telemetry_enabled(cfg)) emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 1, auto_lvl, 5);
                return XDP_DROP;
            }
        }

        if (telemetry_enabled(cfg) && proto == IPPROTO_TCP && (tcp_flags & TCP_FLAG_SYN)) {
            emit_telemetry(4, &src_ip, sport, dport, pkt_len, proto, tcp_flags, 0, 0, 0);
        }

        return XDP_PASS;
    }

    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        struct ip_ban_key_v6 src_ip6;
        __builtin_memcpy(src_ip6.ip, &ip6h->saddr, 16);
        __u8 proto = ip6h->nexthdr;

        __u16 sport = 0, dport = 0;
        __u8 tcp_flags = 0;
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(ip6h + 1);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;
            sport = bpf_ntohs(tcph->source);
            dport = bpf_ntohs(tcph->dest);
            tcp_flags = ((__u8 *)tcph)[13];
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = (void *)(ip6h + 1);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;
            sport = bpf_ntohs(udph->source);
            dport = bpf_ntohs(udph->dest);
        }

        if (is_whitelisted_v6(&src_ip6)) return XDP_PASS;

        __u8 ban_level = 0;
        if (check_ban_v6(&src_ip6, &ban_level)) {
            if (telemetry_enabled(cfg)) emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 1, ban_level, 1);
            return XDP_DROP;
        }

        if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
            if (check_ip_port_v6(&src_ip6, proto, dport, &ban_level)) {
                if (telemetry_enabled(cfg)) emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 1, ban_level, 2);
                return XDP_DROP;
            }
            if (check_port_block(proto, dport)) {
                if (telemetry_enabled(cfg)) emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 1, 0, 3);
                return XDP_DROP;
            }
        }

        if (proto == IPPROTO_TCP) {
            __u8 auto_lvl = 0;
            if (run_syn_detector_v6(&src_ip6, tcp_flags, cfg, &auto_lvl)) {
                if (telemetry_enabled(cfg)) emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 1, auto_lvl, 4);
                return XDP_DROP;
            }
            if (run_portscan_v6(&src_ip6, dport, tcp_flags, cfg, &auto_lvl)) {
                if (telemetry_enabled(cfg)) emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 1, auto_lvl, 5);
                return XDP_DROP;
            }
        }

        if (telemetry_enabled(cfg) && proto == IPPROTO_TCP && (tcp_flags & TCP_FLAG_SYN)) {
            emit_telemetry(6, src_ip6.ip, sport, dport, pkt_len, proto, tcp_flags, 0, 0, 0);
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
