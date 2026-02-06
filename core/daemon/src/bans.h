// SPDX-License-Identifier: MIT

#pragma once

#include "hb_ctx.h"

int hb_ban_ip(hb_ctx *ctx, const char *ip_str, int ttl, int level);
int hb_unban_ip(hb_ctx *ctx, const char *ip_str);

int hb_whitelist_add(hb_ctx *ctx, const char *ip_str);
int hb_whitelist_del(hb_ctx *ctx, const char *ip_str);

int hb_port_block_add(hb_ctx *ctx, const char *proto_str, int port, int ttl);
int hb_port_block_del(hb_ctx *ctx, const char *proto_str, int port);

int hb_ip_port_ban_add(hb_ctx *ctx, const char *ip_str, const char *proto_str, int port, int ttl, int level);
int hb_ip_port_ban_del(hb_ctx *ctx, const char *ip_str, const char *proto_str, int port);

