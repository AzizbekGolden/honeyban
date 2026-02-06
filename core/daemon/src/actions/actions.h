// SPDX-License-Identifier: MIT

#pragma once

#include "../hb_ctx.h"

int hb_actions_load(hb_ctx *ctx);
int hb_actions_reload(hb_ctx *ctx);
void hb_actions_free(hb_ctx *ctx);

int hb_actions_apply_ban(hb_ctx *ctx, const char *action_name, const char *jail_name, const char *filter_name, const char *ip_str,
                         const char *proto, int port, int ttl, int level);
