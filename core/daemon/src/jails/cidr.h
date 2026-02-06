// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>

typedef struct {
    uint8_t ver;      // 4 or 6
    uint8_t prefix;   // bits
    uint8_t addr[16]; // v4 in first 4 bytes
} hb_cidr;

int hb_cidr_parse(const char *s, hb_cidr *out);
int hb_cidr_match_ip_str(const hb_cidr *c, const char *ip_str);

