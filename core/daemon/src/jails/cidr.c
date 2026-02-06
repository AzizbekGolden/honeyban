// SPDX-License-Identifier: MIT

#include "cidr.h"

#include <arpa/inet.h>
#include <string.h>

static int match_bits(const uint8_t *a, const uint8_t *b, uint8_t bits) {
    uint8_t full = bits / 8;
    uint8_t rem = bits % 8;
    if (full) {
        if (memcmp(a, b, full) != 0) return 0;
    }
    if (!rem) return 1;
    uint8_t mask = (uint8_t)(0xFFu << (8 - rem));
    return (a[full] & mask) == (b[full] & mask);
}

int hb_cidr_parse(const char *s, hb_cidr *out) {
    if (!s || !out) return -1;
    memset(out, 0, sizeof(*out));

    char buf[128];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) *slash = '\0';

    if (strchr(buf, ':')) {
        struct in6_addr a6;
        if (inet_pton(AF_INET6, buf, &a6) != 1) return -1;
        out->ver = 6;
        memcpy(out->addr, a6.s6_addr, 16);
        out->prefix = 128;
    } else {
        struct in_addr a4;
        if (inet_pton(AF_INET, buf, &a4) != 1) return -1;
        out->ver = 4;
        memcpy(out->addr, &a4.s_addr, 4);
        out->prefix = 32;
    }

    if (slash) {
        int pfx = atoi(slash + 1);
        int max = out->ver == 6 ? 128 : 32;
        if (pfx < 0 || pfx > max) return -1;
        out->prefix = (uint8_t)pfx;
    }
    return 0;
}

int hb_cidr_match_ip_str(const hb_cidr *c, const char *ip_str) {
    if (!c || !ip_str) return 0;
    uint8_t ip[16] = {0};
    if (c->ver == 6) {
        struct in6_addr a6;
        if (inet_pton(AF_INET6, ip_str, &a6) != 1) return 0;
        memcpy(ip, a6.s6_addr, 16);
        return match_bits(c->addr, ip, c->prefix);
    }
    struct in_addr a4;
    if (inet_pton(AF_INET, ip_str, &a4) != 1) return 0;
    memcpy(ip, &a4.s_addr, 4);
    return match_bits(c->addr, ip, c->prefix);
}

