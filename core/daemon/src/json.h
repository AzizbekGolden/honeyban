// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>

int hb_json_get_string(const char *json, const char *key, char *buf, size_t buf_len);
int hb_json_get_int(const char *json, const char *key, int default_val);
int hb_json_get_bool(const char *json, const char *key, int default_val);

