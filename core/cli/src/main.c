// SPDX-License-Identifier: MIT

#include "honeyban_cli.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *env_default(const char *k, const char *def) {
    const char *v = getenv(k);
    if (v && *v) return v;
    return def;
}

static int parse_int(const char *s, int def) {
    if (!s || !*s) return def;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0') return def;
    if (v > 2147483647L || v < -2147483648L) return def;
    return (int)v;
}

static void usage(void) {
    fprintf(stderr, "HoneyBan CLI\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  honeyban status\n");
    fprintf(stderr, "  honeyban ban <ip> [--ttl 300] [--level 3]\n");
    fprintf(stderr, "  honeyban unban <ip>\n");
    fprintf(stderr, "  honeyban ban ip-port <ip> <port> [--proto tcp|udp] [--ttl 300] [--level 3]\n");
    fprintf(stderr, "  honeyban unban ip-port <ip> <port> [--proto tcp|udp]\n");
    fprintf(stderr, "  honeyban block port <port> [--proto tcp|udp] [--ttl 0]\n");
    fprintf(stderr, "  honeyban unblock port <port> [--proto tcp|udp]\n");
    fprintf(stderr, "  honeyban enable|disable\n");
    fprintf(stderr, "  honeyban whitelist add|del <ip>\n");
    fprintf(stderr, "  honeyban config get\n");
    fprintf(stderr,
            "  honeyban config set [--telemetry on|off] [--journal on|off] [--ssh on|off] [--portscan on|off] [--syn on|off] ...\n");
    fprintf(stderr, "  honeyban profile fast|accurate\n");
    fprintf(stderr, "  honeyban jails reload\n");
    fprintf(stderr, "  honeyban filters reload\n");
    fprintf(stderr, "  honeyban detection reload\n");
    fprintf(stderr, "  honeyban actions reload\n");
    fprintf(stderr, "  honeyban service status|start|stop|restart|logs\n");
    fprintf(stderr, "  honeyban flush\n\n");
    fprintf(stderr, "Environment:\n");
    fprintf(stderr, "  HONEYBAN_SOCKET   Unix socket path (default %s)\n", HONEYBAN_DEFAULT_SOCKET);
    fprintf(stderr, "  HONEYBAN_TIMEOUT  Seconds (default %d)\n", HONEYBAN_DEFAULT_TIMEOUT_SEC);
}

static int parse_on_off(const char *s, int *out) {
    if (!s || !*s) return 0;
    if (!strcmp(s, "on") || !strcmp(s, "true") || !strcmp(s, "1") || !strcmp(s, "yes")) {
        *out = 1;
        return 1;
    }
    if (!strcmp(s, "off") || !strcmp(s, "false") || !strcmp(s, "0") || !strcmp(s, "no")) {
        *out = 0;
        return 1;
    }
    return 0;
}

static void print_errno(const char *msg) {
    fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
}

static int request_and_print(const hb_client_opts *opts, const char *req, int pretty) {
    char resp[4096];
    if (hb_client_request(opts, req, resp, sizeof(resp)) < 0) {
        print_errno("request failed");
        return 1;
    }
    if (pretty && resp[0] == '{') {
        hb_pretty_print_kv(resp);
        return 0;
    }
    printf("%s\n", resp);
    return 0;
}

int main(int argc, char **argv) {
    hb_client_opts opts;
    opts.socket_path = env_default("HONEYBAN_SOCKET", HONEYBAN_DEFAULT_SOCKET);
    opts.timeout_sec = parse_int(env_default("HONEYBAN_TIMEOUT", "1"), HONEYBAN_DEFAULT_TIMEOUT_SEC);
    if (opts.timeout_sec <= 0) opts.timeout_sec = HONEYBAN_DEFAULT_TIMEOUT_SEC;

    if (argc < 2) {
        usage();
        return 2;
    }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
        usage();
        return 0;
    }
    if (!strcmp(cmd, "version")) {
        printf("honeyban %s\n", HONEYBAN_CLI_VERSION);
        return 0;
    }

    if (!strcmp(cmd, "status")) {
        return request_and_print(&opts, "{\"action\":\"stats\"}", 1);
    }
    if (!strcmp(cmd, "enable")) {
        return request_and_print(&opts, "{\"action\":\"enable\"}", 0);
    }
    if (!strcmp(cmd, "disable")) {
        return request_and_print(&opts, "{\"action\":\"disable\"}", 0);
    }
    if (!strcmp(cmd, "flush")) {
        return request_and_print(&opts, "{\"action\":\"flush\"}", 0);
    }

    if (!strcmp(cmd, "service")) {
        return hb_service_exec(argc - 1, argv + 1);
    }

    if (!strcmp(cmd, "jails")) {
        if (argc != 3 || strcmp(argv[2], "reload") != 0) {
            fprintf(stderr, "error: usage: honeyban jails reload\n");
            return 2;
        }
        return request_and_print(&opts, "{\"action\":\"jails_reload\"}", 0);
    }

    if (!strcmp(cmd, "filters")) {
        if (argc != 3 || strcmp(argv[2], "reload") != 0) {
            fprintf(stderr, "error: usage: honeyban filters reload\n");
            return 2;
        }
        return request_and_print(&opts, "{\"action\":\"filters_reload\"}", 0);
    }

    if (!strcmp(cmd, "detection")) {
        if (argc != 3 || strcmp(argv[2], "reload") != 0) {
            fprintf(stderr, "error: usage: honeyban detection reload\n");
            return 2;
        }
        return request_and_print(&opts, "{\"action\":\"detection_reload\"}", 0);
    }

    if (!strcmp(cmd, "actions")) {
        if (argc != 3 || strcmp(argv[2], "reload") != 0) {
            fprintf(stderr, "error: usage: honeyban actions reload\n");
            return 2;
        }
        return request_and_print(&opts, "{\"action\":\"actions_reload\"}", 0);
    }

    if (!strcmp(cmd, "profile")) {
        if (argc != 3) {
            fprintf(stderr, "error: profile requires fast|accurate\n");
            return 2;
        }
        const char *p = argv[2];
        char req[512];
        if (!strcmp(p, "fast")) {
            snprintf(req, sizeof(req),
                     "{\"action\":\"config_set\",\"telemetry_enabled\":false,"
                     "\"syn_enabled\":false,\"portscan_enabled\":false,\"ssh_enabled\":false}");
            return request_and_print(&opts, req, 0);
        }
        if (!strcmp(p, "accurate")) {
            snprintf(req, sizeof(req),
                     "{\"action\":\"config_set\","
                     "\"telemetry_enabled\":true,"
                     "\"syn_enabled\":true,\"portscan_enabled\":true,\"ssh_enabled\":true,"
                     "\"syn_threshold\":300,\"syn_window_sec\":1,"
                     "\"portscan_threshold\":25,\"portscan_window_sec\":10,"
                     "\"ssh_threshold\":8,\"ssh_window_sec\":120,"
                     "\"autoban_level\":3,\"autoban_ttl\":900}");
            return request_and_print(&opts, req, 0);
        }
        fprintf(stderr, "error: profile requires fast|accurate\n");
        return 2;
    }

    if (!strcmp(cmd, "ban")) {
        if (argc < 3) {
            fprintf(stderr, "error: ban requires <ip> or 'ban ip-port <ip> <port>'\n");
            return 2;
        }
        if (!strcmp(argv[2], "ip-port")) {
            if (argc < 5) {
                fprintf(stderr, "error: ban ip-port requires <ip> <port>\n");
                return 2;
            }
            const char *ip = argv[3];
            int port = parse_int(argv[4], -1);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "error: invalid port\n");
                return 2;
            }
            const char *proto = "tcp";
            int ttl = 0;
            int level = 3;
            for (int i = 5; i < argc; i++) {
                if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
                    proto = argv[++i];
                    continue;
                }
                if (!strcmp(argv[i], "--ttl") && i + 1 < argc) {
                    ttl = parse_int(argv[++i], 0);
                    continue;
                }
                if (!strcmp(argv[i], "--level") && i + 1 < argc) {
                    level = parse_int(argv[++i], 3);
                    continue;
                }
                fprintf(stderr, "error: unknown flag: %s\n", argv[i]);
                return 2;
            }
            if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
                fprintf(stderr, "error: proto must be tcp or udp\n");
                return 2;
            }
            char req[256];
            snprintf(req, sizeof(req), "{\"action\":\"ip_port_ban_add\",\"ip\":\"%s\",\"proto\":\"%s\",\"port\":%d,\"ttl\":%d,\"level\":%d}",
                     ip, proto, port, ttl, level);
            return request_and_print(&opts, req, 0);
        }

        const char *ip = argv[2];
        int ttl = 0;
        int level = 3;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--ttl") && i + 1 < argc) {
                ttl = parse_int(argv[++i], 0);
                continue;
            }
            if (!strcmp(argv[i], "--level") && i + 1 < argc) {
                level = parse_int(argv[++i], 3);
                continue;
            }
            fprintf(stderr, "error: unknown flag: %s\n", argv[i]);
            return 2;
        }
        char req[256];
        snprintf(req, sizeof(req), "{\"action\":\"ban\",\"ip\":\"%s\",\"ttl\":%d,\"level\":%d}", ip, ttl, level);
        return request_and_print(&opts, req, 0);
    }

    if (!strcmp(cmd, "unban")) {
        if (argc < 3) {
            fprintf(stderr, "error: unban requires <ip> or 'unban ip-port <ip> <port>'\n");
            return 2;
        }
        if (!strcmp(argv[2], "ip-port")) {
            if (argc < 5) {
                fprintf(stderr, "error: unban ip-port requires <ip> <port>\n");
                return 2;
            }
            const char *ip = argv[3];
            int port = parse_int(argv[4], -1);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "error: invalid port\n");
                return 2;
            }
            const char *proto = "tcp";
            for (int i = 5; i < argc; i++) {
                if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
                    proto = argv[++i];
                    continue;
                }
                fprintf(stderr, "error: unknown flag: %s\n", argv[i]);
                return 2;
            }
            if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
                fprintf(stderr, "error: proto must be tcp or udp\n");
                return 2;
            }
            char req[256];
            snprintf(req, sizeof(req), "{\"action\":\"ip_port_ban_del\",\"ip\":\"%s\",\"proto\":\"%s\",\"port\":%d}", ip, proto, port);
            return request_and_print(&opts, req, 0);
        }

        if (argc != 3) {
            fprintf(stderr, "error: unban requires <ip>\n");
            return 2;
        }
        char req[256];
        snprintf(req, sizeof(req), "{\"action\":\"unban\",\"ip\":\"%s\"}", argv[2]);
        return request_and_print(&opts, req, 0);
    }

    if (!strcmp(cmd, "whitelist")) {
        if (argc != 4) {
            fprintf(stderr, "error: whitelist requires add|del <ip>\n");
            return 2;
        }
        const char *sub = argv[2];
        const char *ip = argv[3];
        char req[256];
        if (!strcmp(sub, "add")) {
            snprintf(req, sizeof(req), "{\"action\":\"whitelist_add\",\"ip\":\"%s\"}", ip);
            return request_and_print(&opts, req, 0);
        }
        if (!strcmp(sub, "del")) {
            snprintf(req, sizeof(req), "{\"action\":\"whitelist_del\",\"ip\":\"%s\"}", ip);
            return request_and_print(&opts, req, 0);
        }
        fprintf(stderr, "error: whitelist requires add|del <ip>\n");
        return 2;
    }

    if (!strcmp(cmd, "block") || !strcmp(cmd, "unblock")) {
        int is_block = !strcmp(cmd, "block");
        if (argc < 4 || strcmp(argv[2], "port") != 0) {
            fprintf(stderr, "error: %s requires: %s port <port> [--proto tcp|udp] [--ttl N]\n", cmd, cmd);
            return 2;
        }
        int port = parse_int(argv[3], -1);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "error: invalid port\n");
            return 2;
        }
        const char *proto = "tcp";
        int ttl = 0;
        for (int i = 4; i < argc; i++) {
            if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
                proto = argv[++i];
                continue;
            }
            if (!strcmp(argv[i], "--ttl") && i + 1 < argc) {
                ttl = parse_int(argv[++i], 0);
                continue;
            }
            fprintf(stderr, "error: unknown flag: %s\n", argv[i]);
            return 2;
        }
        if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
            fprintf(stderr, "error: proto must be tcp or udp\n");
            return 2;
        }
        char req[256];
        if (is_block) {
            snprintf(req, sizeof(req), "{\"action\":\"port_block_add\",\"proto\":\"%s\",\"port\":%d,\"ttl\":%d}", proto, port, ttl);
        } else {
            snprintf(req, sizeof(req), "{\"action\":\"port_block_del\",\"proto\":\"%s\",\"port\":%d}", proto, port);
        }
        return request_and_print(&opts, req, 0);
    }

    if (!strcmp(cmd, "config")) {
        if (argc < 3) {
            fprintf(stderr, "error: config requires get|set\n");
            return 2;
        }
        if (!strcmp(argv[2], "get")) {
            return request_and_print(&opts, "{\"action\":\"config_get\"}", 1);
        }
        if (!strcmp(argv[2], "set")) {
            char req[1024];
            size_t off = 0;
            off += (size_t)snprintf(req + off, sizeof(req) - off, "{\"action\":\"config_set\"");

            for (int i = 3; i < argc; i++) {
                int v = 0;
                if (!strcmp(argv[i], "--telemetry") && i + 1 < argc) {
                    if (!parse_on_off(argv[i + 1], &v)) {
                        fprintf(stderr, "error: invalid on|off value: %s\n", argv[i + 1]);
                        return 2;
                    }
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"telemetry_enabled\":%s", v ? "true" : "false");
                    i++;
                    continue;
                }
                if ((!strcmp(argv[i], "--syn") || !strcmp(argv[i], "--portscan") || !strcmp(argv[i], "--ssh")) && i + 1 < argc) {
                    if (!parse_on_off(argv[i + 1], &v)) {
                        fprintf(stderr, "error: invalid on|off value: %s\n", argv[i + 1]);
                        return 2;
                    }
                    const char *k = !strcmp(argv[i], "--syn") ? "syn_enabled" : (!strcmp(argv[i], "--portscan") ? "portscan_enabled" : "ssh_enabled");
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"%s\":%s", k, v ? "true" : "false");
                    i++;
                    continue;
                }
                if (!strcmp(argv[i], "--journal") && i + 1 < argc) {
                    if (!parse_on_off(argv[i + 1], &v)) {
                        fprintf(stderr, "error: invalid on|off value: %s\n", argv[i + 1]);
                        return 2;
                    }
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"journal_enabled\":%s", v ? "true" : "false");
                    i++;
                    continue;
                }
                if (!strcmp(argv[i], "--syn-threshold") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"syn_threshold\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--syn-window") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"syn_window_sec\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--portscan-threshold") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"portscan_threshold\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--portscan-window") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"portscan_window_sec\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--ssh-threshold") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"ssh_threshold\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--ssh-window") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"ssh_window_sec\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--autoban-level") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"autoban_level\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                if (!strcmp(argv[i], "--autoban-ttl") && i + 1 < argc) {
                    off += (size_t)snprintf(req + off, sizeof(req) - off, ",\"autoban_ttl\":%d", parse_int(argv[++i], -1));
                    continue;
                }
                fprintf(stderr, "error: unknown flag: %s\n", argv[i]);
                return 2;
            }

            off += (size_t)snprintf(req + off, sizeof(req) - off, "}");
            return request_and_print(&opts, req, 0);
        }
        fprintf(stderr, "error: config requires get|set\n");
        return 2;
    }

    fprintf(stderr, "error: unknown command: %s\n", cmd);
    usage();
    return 2;
}
