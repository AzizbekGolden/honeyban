// SPDX-License-Identifier: MIT

#include "api_server.h"
#include "actions/actions.h"
#include "bans.h"
#include "config.h"
#include "detection/detection.h"
#include "filters/filters.h"
#include "json.h"
#include "jails/jails.h"
#include "log.h"
#include "timeutil.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/run/honeyban.sock"
#define SOCKET_GROUP "honeyban"
#define MAX_MSG_LEN 4096
#define MAX_CLIENTS 64

static void send_response(int fd, const char *resp) {
    (void)send(fd, resp, strlen(resp), MSG_NOSIGNAL);
    (void)send(fd, "\n", 1, MSG_NOSIGNAL);
}

static void handle_client(hb_ctx *ctx, int client_fd) {
    char buf[MAX_MSG_LEN];
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }

    char action[32] = {0};
    if (!hb_json_get_string(buf, "action", action, sizeof(action))) {
        send_response(client_fd, "error: missing action");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "ban") || !strcmp(action, "add")) {
        char ip[128] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        int ttl = hb_json_get_int(buf, "ttl", 0);
        int level = hb_json_get_int(buf, "level", 3);
        if (hb_ban_ip(ctx, ip, ttl, level) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: ban failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "unban") || !strcmp(action, "del")) {
        char ip[128] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        (void)hb_unban_ip(ctx, ip);
        send_response(client_fd, "ok");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "ip_port_ban_add")) {
        char ip[128] = {0};
        char proto[8] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        if (!hb_json_get_string(buf, "proto", proto, sizeof(proto))) {
            send_response(client_fd, "error: missing proto");
            close(client_fd);
            return;
        }
        int port = hb_json_get_int(buf, "port", 0);
        int ttl = hb_json_get_int(buf, "ttl", 0);
        int level = hb_json_get_int(buf, "level", 3);
        if (hb_ip_port_ban_add(ctx, ip, proto, port, ttl, level) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: ip_port_ban_add failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "ip_port_ban_del")) {
        char ip[128] = {0};
        char proto[8] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        if (!hb_json_get_string(buf, "proto", proto, sizeof(proto))) {
            send_response(client_fd, "error: missing proto");
            close(client_fd);
            return;
        }
        int port = hb_json_get_int(buf, "port", 0);
        if (hb_ip_port_ban_del(ctx, ip, proto, port) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: ip_port_ban_del failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "port_block_add")) {
        char proto[8] = {0};
        if (!hb_json_get_string(buf, "proto", proto, sizeof(proto))) {
            send_response(client_fd, "error: missing proto");
            close(client_fd);
            return;
        }
        int port = hb_json_get_int(buf, "port", 0);
        int ttl = hb_json_get_int(buf, "ttl", 0);
        if (hb_port_block_add(ctx, proto, port, ttl) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: port_block_add failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "port_block_del")) {
        char proto[8] = {0};
        if (!hb_json_get_string(buf, "proto", proto, sizeof(proto))) {
            send_response(client_fd, "error: missing proto");
            close(client_fd);
            return;
        }
        int port = hb_json_get_int(buf, "port", 0);
        if (hb_port_block_del(ctx, proto, port) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: port_block_del failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "whitelist_add")) {
        char ip[128] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        if (hb_whitelist_add(ctx, ip) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: whitelist_add failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "whitelist_del")) {
        char ip[128] = {0};
        if (!hb_json_get_string(buf, "ip", ip, sizeof(ip))) {
            send_response(client_fd, "error: missing ip");
            close(client_fd);
            return;
        }
        if (hb_whitelist_del(ctx, ip) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: whitelist_del failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "config_get")) {
        hb_config cfg;
        if (hb_config_get(ctx, &cfg) != 0) {
            send_response(client_fd, "error: config_get failed");
            close(client_fd);
            return;
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"ok\",\"flags\":%u,"
                 "\"syn_threshold\":%u,\"syn_window_sec\":%u,"
                 "\"portscan_threshold\":%u,\"portscan_window_sec\":%u,"
                 "\"ssh_threshold\":%u,\"ssh_window_sec\":%u,"
                 "\"autoban_level\":%u,\"autoban_ttl\":%u}",
                 cfg.flags,
                 cfg.syn_threshold, cfg.syn_window_sec,
                 cfg.portscan_threshold, cfg.portscan_window_sec,
                 cfg.ssh_threshold, cfg.ssh_window_sec,
                 cfg.autoban_level, cfg.autoban_ttl);
        send_response(client_fd, resp);
        close(client_fd);
        return;
    }

    if (!strcmp(action, "config_set")) {
        hb_config cfg;
        if (hb_config_get(ctx, &cfg) != 0) {
            memset(&cfg, 0, sizeof(cfg));
            cfg.flags = 1u;
        }

        int enabled = hb_json_get_bool(buf, "enabled", -1);
        if (enabled != -1) {
            if (enabled) cfg.flags |= 1u;
            else cfg.flags &= ~1u;
        }

        int telemetry = hb_json_get_bool(buf, "telemetry_enabled", -1);
        if (telemetry != -1) {
            if (telemetry) cfg.flags |= (1u << 4);
            else cfg.flags &= ~(1u << 4);
        }

        int syn_enabled = hb_json_get_bool(buf, "syn_enabled", -1);
        if (syn_enabled != -1) {
            if (syn_enabled) cfg.flags |= (1u << 1);
            else cfg.flags &= ~(1u << 1);
        }
        int portscan_enabled = hb_json_get_bool(buf, "portscan_enabled", -1);
        if (portscan_enabled != -1) {
            if (portscan_enabled) cfg.flags |= (1u << 2);
            else cfg.flags &= ~(1u << 2);
        }
        int ssh_enabled = hb_json_get_bool(buf, "ssh_enabled", -1);
        if (ssh_enabled != -1) {
            if (ssh_enabled) cfg.flags |= (1u << 3);
            else cfg.flags &= ~(1u << 3);
        }

        int journal_enabled = hb_json_get_bool(buf, "journal_enabled", -1);
        if (journal_enabled != -1) {
            if (journal_enabled) cfg.flags |= (1u << 5);
            else cfg.flags &= ~(1u << 5);
        }

        cfg.syn_threshold = (uint32_t)hb_json_get_int(buf, "syn_threshold", (int)cfg.syn_threshold);
        cfg.syn_window_sec = (uint32_t)hb_json_get_int(buf, "syn_window_sec", (int)cfg.syn_window_sec);
        cfg.portscan_threshold = (uint32_t)hb_json_get_int(buf, "portscan_threshold", (int)cfg.portscan_threshold);
        cfg.portscan_window_sec = (uint32_t)hb_json_get_int(buf, "portscan_window_sec", (int)cfg.portscan_window_sec);
        cfg.ssh_threshold = (uint32_t)hb_json_get_int(buf, "ssh_threshold", (int)cfg.ssh_threshold);
        cfg.ssh_window_sec = (uint32_t)hb_json_get_int(buf, "ssh_window_sec", (int)cfg.ssh_window_sec);
        cfg.autoban_level = (uint32_t)hb_json_get_int(buf, "autoban_level", (int)cfg.autoban_level);
        cfg.autoban_ttl = (uint32_t)hb_json_get_int(buf, "autoban_ttl", (int)cfg.autoban_ttl);

        if (hb_config_set(ctx, &cfg) != 0) {
            send_response(client_fd, "error: config_set failed");
            close(client_fd);
            return;
        }

        ctx->cfg = cfg;
        send_response(client_fd, "ok");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "enable") || !strcmp(action, "disable")) {
        hb_config cfg;
        if (hb_config_get(ctx, &cfg) != 0) {
            send_response(client_fd, "error: enable/disable failed");
            close(client_fd);
            return;
        }
        if (!strcmp(action, "enable")) cfg.flags |= 1u;
        else cfg.flags &= ~1u;
        if (hb_config_set(ctx, &cfg) != 0) {
            send_response(client_fd, "error: enable/disable failed");
            close(client_fd);
            return;
        }
        ctx->cfg = cfg;
        send_response(client_fd, "ok");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "stats")) {
        uint64_t uptime = hb_mono_sec() - ctx->start_mono;
        char resp[512];
        pthread_mutex_lock(&ctx->lock);
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"ok\",\"total_bans\":%llu,\"total_unbans\":%llu,"
                 "\"total_port_blocks\":%llu,\"total_errors\":%llu,"
                 "\"uptime_seconds\":%llu,\"interface\":\"%s\"}",
                 (unsigned long long)ctx->total_bans,
                 (unsigned long long)ctx->total_unbans,
                 (unsigned long long)ctx->total_port_blocks,
                 (unsigned long long)ctx->total_errors,
                 (unsigned long long)uptime,
                 ctx->iface);
        pthread_mutex_unlock(&ctx->lock);
        send_response(client_fd, resp);
        close(client_fd);
        return;
    }

    if (!strcmp(action, "flush")) {
        // Cleanup is done periodically; this is a hint.
        send_response(client_fd, "ok");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "jails_reload")) {
        if (hb_jails_reload(ctx) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: jails_reload failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "filters_reload")) {
        if (hb_filters_reload(ctx) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: filters_reload failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "detection_reload")) {
        if (hb_detection_reload(ctx) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: detection_reload failed");
        close(client_fd);
        return;
    }

    if (!strcmp(action, "actions_reload")) {
        if (hb_actions_reload(ctx) == 0) send_response(client_fd, "ok");
        else send_response(client_fd, "error: actions_reload failed");
        close(client_fd);
        return;
    }

    send_response(client_fd, "error: unknown action");
    close(client_fd);
}

static void *server_thread(void *arg) {
    hb_ctx *ctx = (hb_ctx *)arg;

    unlink(SOCKET_PATH);

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        hb_log_error("socket() failed: %s", strerror(errno));
        return NULL;
    }

    int flags = fcntl(server_fd, F_GETFL, 0);
    (void)fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        hb_log_error("bind() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    chmod(SOCKET_PATH, 0660);
    struct group *grp = getgrnam(SOCKET_GROUP);
    if (grp) {
        (void)chown(SOCKET_PATH, 0, grp->gr_gid);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0) {
        hb_log_error("listen() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    hb_log_info("socket listening: %s", SOCKET_PATH);

    while (ctx->running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            }
            if (ctx->running) hb_log_error("accept() failed: %s", strerror(errno));
            continue;
        }

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        handle_client(ctx, client_fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return NULL;
}

int hb_api_server_start(hb_ctx *ctx) {
    if (!ctx) return -1;
    if (pthread_create(&ctx->socket_thread, NULL, server_thread, ctx) != 0) return -1;
    return 0;
}
