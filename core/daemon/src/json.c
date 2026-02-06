// SPDX-License-Identifier: MIT

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hb_json_get_string(const char *json, const char *key, char *buf, size_t buf_len) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"", key);

    const char *start = strstr(json, search);
    if (!start) return 0;

    start += strlen(search);
    const char *end = strchr(start, '"');
    if (!end) return 0;

    size_t len = (size_t)(end - start);
    if (len >= buf_len) len = buf_len - 1;

    memcpy(buf, start, len);
    buf[len] = '\0';
    return 1;
}

int hb_json_get_int(const char *json, const char *key, int default_val) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char *start = strstr(json, search);
    if (!start) return default_val;

    start += strlen(search);
    while (*start == ' ' || *start == '\t') start++;
    if (*start == '"') start++;
    return atoi(start);
}

int hb_json_get_bool(const char *json, const char *key, int default_val) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char *start = strstr(json, search);
    if (!start) return default_val;

    start += strlen(search);
    while (*start == ' ' || *start == '\t') start++;

    if (!strncmp(start, "true", 4)) return 1;
    if (!strncmp(start, "false", 5)) return 0;
    return default_val;
}

