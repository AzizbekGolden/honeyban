// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>

// Keep in sync with core/bpf/honeyban_xdp.bpf.c.

typedef struct {
    uint32_t ip;
    uint32_t padding[3];
} hb_ip_ban_key_v4;

typedef struct {
    uint8_t ip[16];
} hb_ip_ban_key_v6;

typedef struct {
    uint64_t ban_time;   // monotonic seconds since boot
    uint32_t ban_level;  // 1-5
    uint32_t ttl;        // seconds (0 = permanent)
} hb_ban_value;

typedef struct {
    uint8_t proto; // IPPROTO_*
    uint8_t pad;
    uint16_t dport; // host order
} hb_port_key;

typedef struct {
    uint32_t ip;     // network order
    hb_port_key p;   // host order
    uint32_t pad;
} hb_ip_port_key_v4;

typedef struct {
    hb_ip_ban_key_v6 ip6;
    hb_port_key p;
} hb_ip_port_key_v6;

typedef struct {
    uint64_t timestamp;
    uint8_t ip_version; // 4 or 6
    uint8_t action;     // 0 pass, 1 drop
    uint8_t protocol;
    uint8_t tcp_flags;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t pkt_len;
    uint8_t ban_level;
    // reason:
    // 0 none
    // 1 ip_ban
    // 2 ip_port_ban
    // 3 port_block
    // 4 autoban_synflood
    // 5 autoban_portscan
    uint8_t reason;
    uint8_t src_ip6[16];
} hb_telemetry_event;

typedef struct {
    // Bit 0: XDP enabled
    // Bit 1: synflood detector enabled (userspace)
    // Bit 2: portscan detector enabled (userspace)
    // Bit 3: ssh detector enabled (userspace)
    // Bit 4: telemetry enabled
    // Bit 5: journal filters enabled (userspace)
    uint32_t flags;

    // Userspace detector tuning (BPF ignores these fields).
    uint32_t syn_threshold;
    uint32_t syn_window_sec;
    uint32_t portscan_threshold;
    uint32_t portscan_window_sec;
    uint32_t ssh_threshold;
    uint32_t ssh_window_sec;
    uint32_t autoban_level;
    uint32_t autoban_ttl;
    uint32_t reserved0;
} hb_config;
