// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>

#define HONEYBAN_CLI_VERSION "0.2.0"
#define HONEYBAN_DEFAULT_SOCKET "/run/honeyban.sock"
#define HONEYBAN_DEFAULT_TIMEOUT_SEC 1

typedef struct {
    const char *socket_path;
    int timeout_sec;
} hb_client_opts;

int hb_client_request(const hb_client_opts *opts, const char *req_json, char *resp, size_t resp_cap);
void hb_pretty_print_kv(const char *json);

int hb_service_exec(int argc, char **argv);

