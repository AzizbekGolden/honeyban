// SPDX-License-Identifier: MIT

#pragma once

#include "hb_ctx.h"

int hb_bpf_load_and_attach(hb_ctx *ctx, const char *iface, const char *bpf_obj_path);
void hb_bpf_detach_and_close(hb_ctx *ctx);

