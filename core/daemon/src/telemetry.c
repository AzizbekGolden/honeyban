// SPDX-License-Identifier: MIT

#include "telemetry.h"

#include "detection/detection.h"
#include "log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

static int on_rb_event(void *ctxp, void *data, size_t size) {
    hb_ctx *ctx = (hb_ctx *)ctxp;
    if (!ctx || !data) return 0;
    if (size < sizeof(hb_telemetry_event)) return 0;

    const hb_telemetry_event *ev = (const hb_telemetry_event *)data;

    hb_detection_on_telemetry(ctx, ev);

    return 0;
}

static void *telemetry_thread(void *arg) {
    hb_ctx *ctx = (hb_ctx *)arg;

    ctx->rb = ring_buffer__new(ctx->map_fd_rb, on_rb_event, ctx, NULL);
    if (!ctx->rb) {
        hb_log_error("ring_buffer__new failed");
        return NULL;
    }

    hb_log_info("telemetry consumer started");

    while (ctx->running) {
        int r = ring_buffer__poll(ctx->rb, 100);
        if (r < 0) {
            if (r == -EINTR) continue;
            char errbuf[128];
            libbpf_strerror(-r, errbuf, sizeof(errbuf));
            hb_log_error("ring_buffer__poll failed: %s", errbuf);
            usleep(100000);
        }
    }

    ring_buffer__free(ctx->rb);
    ctx->rb = NULL;
    hb_log_info("telemetry consumer stopped");
    return NULL;
}

int hb_telemetry_start(hb_ctx *ctx) {
    if (!ctx) return -1;
    if (pthread_create(&ctx->telemetry_thread, NULL, telemetry_thread, ctx) != 0) return -1;
    return 0;
}

void hb_telemetry_stop(hb_ctx *ctx) {
    (void)ctx;
}
