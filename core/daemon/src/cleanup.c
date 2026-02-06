// SPDX-License-Identifier: MIT

#include "cleanup.h"
#include "log.h"
#include "timeutil.h"

#include <bpf/bpf.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define CLEANUP_INTERVAL_SEC 15

static int is_expired(const hb_ban_value *v, uint64_t now) {
    if (!v) return 0;
    if (v->ttl == 0) return 0;
    return now > v->ban_time + v->ttl;
}

static int cleanup_map(int map_fd, size_t key_sz) {
    // key0 can be NULL to start.
    uint8_t key[256];
    uint8_t next_key[256];
    hb_ban_value val;
    int cleaned = 0;
    if (key_sz > sizeof(key)) return 0;

    uint64_t now = hb_mono_sec();

    if (bpf_map_get_next_key(map_fd, NULL, key) != 0) return 0;

    for (;;) {
        if (bpf_map_lookup_elem(map_fd, key, &val) == 0) {
            if (is_expired(&val, now)) {
                (void)bpf_map_delete_elem(map_fd, key);
                cleaned++;
            }
        }

        if (bpf_map_get_next_key(map_fd, key, next_key) != 0) break;
        memcpy(key, next_key, key_sz);
    }

    return cleaned;
}

static void *cleanup_thread(void *arg) {
    hb_ctx *ctx = (hb_ctx *)arg;
    while (ctx->running) {
        sleep(CLEANUP_INTERVAL_SEC);
        if (!ctx->running) break;

        pthread_mutex_lock(&ctx->lock);
        int c1 = cleanup_map(ctx->map_fd_ip_ban_v4, sizeof(hb_ip_ban_key_v4));
        int c2 = cleanup_map(ctx->map_fd_ip_ban_v6, sizeof(hb_ip_ban_key_v6));
        int c3 = cleanup_map(ctx->map_fd_port_block, sizeof(hb_port_key));
        int c4 = cleanup_map(ctx->map_fd_ip_port_v4, sizeof(hb_ip_port_key_v4));
        int c5 = cleanup_map(ctx->map_fd_ip_port_v6, sizeof(hb_ip_port_key_v6));
        pthread_mutex_unlock(&ctx->lock);

        int total = c1 + c2 + c3 + c4 + c5;
        if (total > 0) hb_log_info("cleanup expired entries: %d", total);
    }
    return NULL;
}

int hb_cleanup_start(hb_ctx *ctx) {
    if (!ctx) return -1;
    if (pthread_create(&ctx->cleanup_thread, NULL, cleanup_thread, ctx) != 0) return -1;
    return 0;
}
