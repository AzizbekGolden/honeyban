// SPDX-License-Identifier: MIT

#pragma once

#include "../hb_ctx.h"

int hb_jails_load(hb_ctx *ctx);
int hb_jails_reload(hb_ctx *ctx);
void hb_jails_free(hb_ctx *ctx);

// Telemetry (packet-level) signals, used for synflood/portscan/ssh connect-rate.
void hb_jails_on_telemetry(hb_ctx *ctx, const hb_telemetry_event *ev);

// Journal filter matches (systemd-journald stream).
void hb_jails_on_filter_fail(hb_ctx *ctx, const char *filter_name, const char *ip_str);
