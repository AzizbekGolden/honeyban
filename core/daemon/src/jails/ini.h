// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>

typedef void (*hb_ini_kv_fn)(void *userdata, const char *section, const char *key, const char *value);

// Minimal INI parser:
// - Comments: lines starting with # or ;
// - Section: [name]
// - KV: key=value
// - Whitespace around key/value is trimmed
int hb_ini_parse_file(const char *path, hb_ini_kv_fn on_kv, void *userdata);

