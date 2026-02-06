// SPDX-License-Identifier: MIT

#pragma once

#include "../../include/honeyban_bpf.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t ver;   // 4 or 6
    uint8_t ip[16]; // network order; v4 stored in first 4 bytes
} hb_det_key;

void hb_det_key_from_event(hb_det_key *out, const hb_telemetry_event *ev);
uint32_t hb_det_key_hash(const hb_det_key *k);
int hb_det_key_equal(const hb_det_key *a, const hb_det_key *b);
int hb_det_key_to_string(const hb_det_key *k, char *buf, size_t cap);

