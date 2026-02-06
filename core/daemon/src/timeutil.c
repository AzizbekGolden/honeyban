// SPDX-License-Identifier: MIT

#include "timeutil.h"

#include <time.h>

uint64_t hb_mono_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec;
}

