// SPDX-License-Identifier: MIT

#pragma once

#include "honeyban_bpf.h"

#include <bpf/libbpf.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

typedef struct hb_ctx hb_ctx;

struct hb_ctx {
    volatile sig_atomic_t running;

    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int ifindex;
    char iface[IF_NAMESIZE];
    uint32_t xdp_flags;

    // Map fds
    int map_fd_ip_ban_v4;
    int map_fd_ip_ban_v6;
    int map_fd_whitelist_v4;
    int map_fd_whitelist_v6;
    int map_fd_control;
    int map_fd_port_block;
    int map_fd_ip_port_v4;
    int map_fd_ip_port_v6;
    int map_fd_rb;

    struct ring_buffer *rb;

    pthread_t socket_thread;
    pthread_t cleanup_thread;
    pthread_t telemetry_thread;
    pthread_t journal_thread;

    pthread_mutex_t lock;
    pthread_mutex_t jails_mu;
    pthread_mutex_t filters_mu;
    pthread_mutex_t detection_mu;
    pthread_mutex_t actions_mu;

    uint64_t total_bans;
    uint64_t total_unbans;
    uint64_t total_port_blocks;
    uint64_t total_errors;
    uint64_t start_mono;

    hb_config cfg;

    void *jails;
    void *filters;
    void *detection;
    void *actions;
};
