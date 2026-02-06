// SPDX-License-Identifier: MIT

#include "ipkey.h"

#include <arpa/inet.h>
#include <string.h>

static uint32_t fnv1a32(const uint8_t *data, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

void hb_det_key_from_event(hb_det_key *out, const hb_telemetry_event *ev) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!ev) return;

    out->ver = ev->ip_version;
    if (ev->ip_version == 6) {
        memcpy(out->ip, ev->src_ip6, 16);
    } else {
        out->ver = 4;
        memcpy(out->ip, ev->src_ip6, 4);
    }
}

uint32_t hb_det_key_hash(const hb_det_key *k) {
    if (!k) return 0;
    uint8_t tmp[17];
    tmp[0] = k->ver;
    if (k->ver == 6) memcpy(&tmp[1], k->ip, 16);
    else {
        memset(&tmp[1], 0, 16);
        memcpy(&tmp[1], k->ip, 4);
    }
    return fnv1a32(tmp, sizeof(tmp));
}

int hb_det_key_equal(const hb_det_key *a, const hb_det_key *b) {
    if (!a || !b) return 0;
    if (a->ver != b->ver) return 0;
    if (a->ver == 6) return memcmp(a->ip, b->ip, 16) == 0;
    return memcmp(a->ip, b->ip, 4) == 0;
}

int hb_det_key_to_string(const hb_det_key *k, char *buf, size_t cap) {
    if (!k || !buf || cap == 0) return -1;
    buf[0] = '\0';

    if (k->ver == 6) {
        struct in6_addr a6;
        memcpy(a6.s6_addr, k->ip, 16);
        if (!inet_ntop(AF_INET6, &a6, buf, (socklen_t)cap)) return -1;
        return 0;
    }

    struct in_addr a4;
    memcpy(&a4.s_addr, k->ip, 4);
    if (!inet_ntop(AF_INET, &a4, buf, (socklen_t)cap)) return -1;
    return 0;
}

