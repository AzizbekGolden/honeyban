// SPDX-License-Identifier: MIT

#pragma once

#include "../hb_ctx.h"

int hb_detection_init(hb_ctx *ctx);
int hb_detection_reload(hb_ctx *ctx);
void hb_detection_free(hb_ctx *ctx);

void hb_detection_on_telemetry(hb_ctx *ctx, const hb_telemetry_event *ev);
void hb_detection_on_filter_fail(hb_ctx *ctx, const char *filter_name, const char *ip_str);

