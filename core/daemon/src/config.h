// SPDX-License-Identifier: MIT

#pragma once

#include "hb_ctx.h"

int hb_config_get(hb_ctx *ctx, hb_config *out);
int hb_config_set(hb_ctx *ctx, const hb_config *cfg);
int hb_config_init_defaults(hb_ctx *ctx);
int hb_config_apply_env(hb_ctx *ctx);
int hb_config_apply_profile(hb_ctx *ctx);
