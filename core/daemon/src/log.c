// SPDX-License-Identifier: MIT

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static void log_prefix(FILE *fp, const char *lvl) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, lvl);
}

void hb_log_info(const char *fmt, ...) {
    va_list args;
    log_prefix(stdout, "INFO");
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
}

void hb_log_error(const char *fmt, ...) {
    va_list args;
    log_prefix(stderr, "ERROR");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
}

