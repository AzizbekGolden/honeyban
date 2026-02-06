// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include "hb_ctx.h"

#include "api_server.h"
#include "actions/actions.h"
#include "bpf_loader.h"
#include "cleanup.h"
#include "config.h"
#include "detection/detection.h"
#include "filters/filters.h"
#include "journal.h"
#include "log.h"
#include "telemetry.h"
#include "timeutil.h"

#include "jails/jails.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static hb_ctx g_ctx;

static void on_signal(int signo) {
    (void)signo;
    g_ctx.running = 0;
}

static const char *pick_bpf_obj_path(void) {
    const char *env = getenv("HONEYBAN_BPF_OBJ_PATH");
    if (env && *env) return env;

    static const char *paths[] = {
        "/usr/local/lib/honeyban/honeyban_xdp.bpf.o",
        "/usr/lib/honeyban/honeyban_xdp.bpf.o",
        "./build/honeyban_xdp.bpf.o",
        NULL,
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], R_OK) == 0) return paths[i];
    }
    return NULL;
}

static const char *pick_iface(int argc, char **argv) {
    if (argc > 1 && argv[1] && argv[1][0] != '-') return argv[1];
    const char *env = getenv("HONEYBAN_IFACE");
    if (env && *env) return env;
    return "eth0";
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [interface]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Environment:\n");
    fprintf(stderr, "  HONEYBAN_IFACE         Interface (default eth0)\n");
    fprintf(stderr, "  HONEYBAN_BPF_OBJ_PATH  Path to honeyban_xdp.bpf.o\n");
}

int main(int argc, char **argv) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.running = 1;

    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        usage(argv[0]);
        return 0;
    }

    if (geteuid() != 0) {
        hb_log_error("must run as root");
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &r);

    pthread_mutex_init(&g_ctx.lock, NULL);
    pthread_mutex_init(&g_ctx.jails_mu, NULL);
    pthread_mutex_init(&g_ctx.filters_mu, NULL);
    pthread_mutex_init(&g_ctx.detection_mu, NULL);
    pthread_mutex_init(&g_ctx.actions_mu, NULL);
    g_ctx.start_mono = hb_mono_sec();

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    const char *iface = pick_iface(argc, argv);
    const char *bpf_obj = pick_bpf_obj_path();
    if (!bpf_obj) {
        hb_log_error("BPF object not found. Set HONEYBAN_BPF_OBJ_PATH or install core/bpf.");
        return 1;
    }

    hb_log_info("starting honeyban-daemon iface=%s bpf=%s", iface, bpf_obj);

    if (hb_bpf_load_and_attach(&g_ctx, iface, bpf_obj) < 0) {
        hb_bpf_detach_and_close(&g_ctx);
        return 1;
    }

    if (hb_config_init_defaults(&g_ctx) < 0) {
        hb_bpf_detach_and_close(&g_ctx);
        return 1;
    }
    (void)hb_config_apply_profile(&g_ctx);
    (void)hb_config_apply_env(&g_ctx);

    if (hb_actions_load(&g_ctx) < 0) {
        hb_log_error("actions load failed");
        g_ctx.running = 0;
    }

    if (hb_jails_load(&g_ctx) < 0) {
        hb_log_error("jails load failed");
        g_ctx.running = 0;
    }

    if (g_ctx.running && (g_ctx.cfg.flags & (1u << 5))) {
        if (hb_filters_load(&g_ctx) < 0) {
            hb_log_error("filters load failed");
            g_ctx.running = 0;
        }
    }

    if (g_ctx.running && hb_detection_init(&g_ctx) < 0) {
        hb_log_error("detection init failed");
        g_ctx.running = 0;
    }

    if (g_ctx.running && hb_api_server_start(&g_ctx) < 0) {
        hb_log_error("api server start failed");
        g_ctx.running = 0;
    }
    if (g_ctx.running && hb_cleanup_start(&g_ctx) < 0) {
        hb_log_error("cleanup start failed");
        g_ctx.running = 0;
    }
    if (g_ctx.running && hb_telemetry_start(&g_ctx) < 0) {
        hb_log_error("telemetry start failed");
        g_ctx.running = 0;
    }
    if (g_ctx.running) (void)hb_journal_start(&g_ctx);

    while (g_ctx.running) {
        sleep(1);
    }

    hb_log_info("shutting down");

    // Join threads
    if (g_ctx.socket_thread) pthread_join(g_ctx.socket_thread, NULL);
    if (g_ctx.cleanup_thread) pthread_join(g_ctx.cleanup_thread, NULL);
    if (g_ctx.telemetry_thread) pthread_join(g_ctx.telemetry_thread, NULL);
    if (g_ctx.journal_thread) pthread_join(g_ctx.journal_thread, NULL);

    hb_bpf_detach_and_close(&g_ctx);

    hb_jails_free(&g_ctx);
    hb_filters_free(&g_ctx);
    hb_detection_free(&g_ctx);
    hb_actions_free(&g_ctx);

    pthread_mutex_destroy(&g_ctx.lock);
    pthread_mutex_destroy(&g_ctx.jails_mu);
    pthread_mutex_destroy(&g_ctx.filters_mu);
    pthread_mutex_destroy(&g_ctx.detection_mu);
    pthread_mutex_destroy(&g_ctx.actions_mu);

    hb_log_info("stopped");
    return 0;
}
