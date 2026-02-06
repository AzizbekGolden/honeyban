// SPDX-License-Identifier: MIT

#pragma once

#include "../hb_ctx.h"

#include <stddef.h>
#include <stdint.h>

// Filters are loaded from /etc/honeyban/filters.d/*.conf (INI sections).
// They are used by log consumers (journald or file tail backend) to turn log lines
// into "auth failure" signals with extracted IP and false-positive suppression.

int hb_filters_load(hb_ctx *ctx);
int hb_filters_reload(hb_ctx *ctx);
void hb_filters_free(hb_ctx *ctx);

// Collect unique syslog identifiers used by enabled filters. Returns count.
// out_ids is a flat buffer with `stride` bytes per entry.
size_t hb_filters_get_syslog_identifiers(hb_ctx *ctx, char *out_ids, size_t max_ids, size_t stride, uint32_t *out_sig);

// Match one log message. Returns 1 if matched and extracted a valid IP, else 0.
int hb_filters_match(hb_ctx *ctx, const char *syslog_id, const char *message, char *out_filter, size_t out_filter_cap,
                     char *out_ip, size_t out_ip_cap);
