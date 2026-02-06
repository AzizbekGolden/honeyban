// SPDX-License-Identifier: MIT

#include "journal.h"

#include "detection/detection.h"
#include "filters/filters.h"
#include "log.h"
#include "timeutil.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HB_MAX_LOG_FILES 32
#define HB_LOG_LINE_MAX 2048
#define HB_LOG_POLL_USEC 200000

typedef struct {
    char path[512];
    FILE *fp;
    dev_t dev;
    ino_t ino;
    off_t off;
} hb_log_file_state;

typedef enum {
    HB_LOG_BACKEND_AUTO = 0,
    HB_LOG_BACKEND_JOURNAL = 1,
    HB_LOG_BACKEND_FILE = 2,
} hb_log_backend;

static const char *default_log_files(void) {
    return "/var/log/auth.log,/var/log/secure,/var/log/messages,/var/log/syslog";
}

static int parse_on_off(const char *s, int defv) {
    if (!s || !*s) return defv;
    if (!strcmp(s, "1") || !strcmp(s, "true") || !strcmp(s, "on") || !strcmp(s, "yes")) return 1;
    if (!strcmp(s, "0") || !strcmp(s, "false") || !strcmp(s, "off") || !strcmp(s, "no")) return 0;
    return defv;
}

#ifdef HONEYBAN_WITH_SYSTEMD
static hb_log_backend parse_backend_mode(void) {
    const char *v = getenv("HONEYBAN_LOG_BACKEND");
    if (!v || !*v || !strcmp(v, "auto")) return HB_LOG_BACKEND_AUTO;
    if (!strcmp(v, "journal")) return HB_LOG_BACKEND_JOURNAL;
    if (!strcmp(v, "file")) return HB_LOG_BACKEND_FILE;
    return HB_LOG_BACKEND_AUTO;
}
#endif

static size_t parse_csv_paths(const char *csv, hb_log_file_state *out, size_t maxn) {
    if (!csv || !*csv || !out || maxn == 0) return 0;
    size_t n = 0;
    const char *p = csv;
    while (*p && n < maxn) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',' && *end != '\r' && *end != '\n') end++;
        size_t len = (size_t)(end - p);
        while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
        if (len > 0 && len < sizeof(out[n].path)) {
            memset(&out[n], 0, sizeof(out[n]));
            memcpy(out[n].path, p, len);
            out[n].path[len] = '\0';
            n++;
        }
        p = end;
        while (*p && *p != ',') p++;
    }
    return n;
}

static const char *skip_to_message(const char *line) {
    if (!line) return "";
    const char *sep = strstr(line, ": ");
    if (!sep) return line;
    return sep + 2;
}

static void extract_syslog_identifier(const char *line, char *out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!line || !*line) return;

    const char *sep = strstr(line, ": ");
    if (!sep) return;

    const char *end = sep;
    while (end > line && isspace((unsigned char)end[-1])) end--;
    const char *start = end;
    while (start > line && !isspace((unsigned char)start[-1])) start--;
    if (start >= end) return;

    size_t len = (size_t)(end - start);
    if (len >= cap) len = cap - 1;
    memcpy(out, start, len);
    out[len] = '\0';

    char *pid = strchr(out, '[');
    if (pid) *pid = '\0';
}

static int open_log_file(hb_log_file_state *st, int from_start) {
    if (!st || !st->path[0]) return -1;
    FILE *fp = fopen(st->path, "r");
    if (!fp) return -1;

    struct stat sb;
    if (stat(st->path, &sb) == 0) {
        st->dev = sb.st_dev;
        st->ino = sb.st_ino;
    } else {
        st->dev = 0;
        st->ino = 0;
    }

    if (!from_start) (void)fseek(fp, 0, SEEK_END);
    st->off = ftell(fp);
    st->fp = fp;
    return 0;
}

static int ensure_log_file_ready(hb_log_file_state *st) {
    if (!st) return -1;
    int read_from_start = parse_on_off(getenv("HONEYBAN_LOG_READ_FROM_START"), 0);

    if (!st->fp) return open_log_file(st, read_from_start);

    struct stat sb;
    if (stat(st->path, &sb) != 0) return 0;

    if (st->dev != sb.st_dev || st->ino != sb.st_ino) {
        fclose(st->fp);
        st->fp = NULL;
        st->dev = 0;
        st->ino = 0;
        st->off = 0;
        return open_log_file(st, 1);
    }

    if (sb.st_size < st->off) {
        (void)fseek(st->fp, 0, SEEK_SET);
        st->off = 0;
    }
    return 0;
}

static void close_log_files(hb_log_file_state *files, size_t n) {
    if (!files) return;
    for (size_t i = 0; i < n; i++) {
        if (files[i].fp) {
            fclose(files[i].fp);
            files[i].fp = NULL;
        }
    }
}

static void process_log_file(hb_ctx *ctx, hb_log_file_state *st) {
    if (!ctx || !st) return;
    if (ensure_log_file_ready(st) != 0 || !st->fp) return;

    char line[HB_LOG_LINE_MAX];
    unsigned processed = 0;
    while (processed < 256 && fgets(line, sizeof(line), st->fp) != NULL) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        st->off = ftell(st->fp);
        if (!line[0]) continue;

        char syslog_id[64] = {0};
        extract_syslog_identifier(line, syslog_id, sizeof(syslog_id));

        const char *msg = skip_to_message(line);
        if (!msg || !*msg) msg = line;

        char filter_name[64];
        char ip[128];
        if (!hb_filters_match(ctx, syslog_id, msg, filter_name, sizeof(filter_name), ip, sizeof(ip))) continue;
        hb_detection_on_filter_fail(ctx, filter_name, ip);
        processed++;
    }

    if (st->fp && feof(st->fp)) clearerr(st->fp);
}

static void run_file_log_loop(hb_ctx *ctx) {
    const char *paths = getenv("HONEYBAN_LOG_FILES");
    if (!paths || !*paths) paths = default_log_files();

    hb_log_file_state files[HB_MAX_LOG_FILES];
    memset(files, 0, sizeof(files));
    size_t nfiles = parse_csv_paths(paths, files, HB_MAX_LOG_FILES);
    if (nfiles == 0) {
        hb_log_error("logtail: no log files configured");
        return;
    }

    hb_log_info("logtail: started files=%zu", nfiles);
    while (ctx->running) {
        for (size_t i = 0; i < nfiles; i++) process_log_file(ctx, &files[i]);
        usleep(HB_LOG_POLL_USEC);
    }
    close_log_files(files, nfiles);
    hb_log_info("logtail: stopped");
}

#ifndef HONEYBAN_WITH_SYSTEMD

static void *file_thread(void *arg) {
    hb_ctx *ctx = (hb_ctx *)arg;
    run_file_log_loop(ctx);
    return NULL;
}

#else

#include <systemd/sd-journal.h>

static int get_field_value(sd_journal *j, const char *key, char *buf, size_t cap) {
    if (!j || !key || !buf || cap == 0) return -1;
    buf[0] = '\0';
    const void *data = NULL;
    size_t len = 0;
    if (sd_journal_get_data(j, key, &data, &len) < 0) return -1;
    const char *field = (const char *)data;
    const char *eq = strchr(field, '=');
    if (!eq) return -1;
    eq++;
    size_t n = strlen(eq);
    if (n >= cap) n = cap - 1;
    memcpy(buf, eq, n);
    buf[n] = '\0';
    return 0;
}

static int open_and_match(sd_journal **out, char ids[][64], size_t n) {
    if (!out) return -1;
    *out = NULL;

    if (n == 0) {
        hb_log_info("journal: no syslog identifiers from filters; skipping");
        return -1;
    }

    sd_journal *j = NULL;
    if (sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY) < 0) {
        hb_log_error("journal: sd_journal_open failed");
        return -1;
    }

    (void)sd_journal_flush_matches(j);
    for (size_t i = 0; i < n; i++) {
        if (i > 0) (void)sd_journal_add_disjunction(j);
        char match[128];
        snprintf(match, sizeof(match), "SYSLOG_IDENTIFIER=%s", ids[i]);
        (void)sd_journal_add_match(j, match, 0);
    }

    (void)sd_journal_seek_tail(j);
    (void)sd_journal_next(j);

    *out = j;
    return 0;
}

static void *journal_thread(void *arg) {
    hb_ctx *ctx = (hb_ctx *)arg;
    hb_log_backend backend = parse_backend_mode();

    if (backend == HB_LOG_BACKEND_FILE) {
        run_file_log_loop(ctx);
        return NULL;
    }

    sd_journal *j = NULL;
    uint32_t sig = 0;

    char ids[32][64];
    size_t n = hb_filters_get_syslog_identifiers(ctx, (char *)ids, 32, sizeof(ids[0]), &sig);

    if (open_and_match(&j, ids, n) != 0) {
        if (backend == HB_LOG_BACKEND_AUTO) {
            hb_log_info("journal: unavailable, switching to file backend");
            run_file_log_loop(ctx);
            return NULL;
        }
        hb_log_info("journal: not started");
        return NULL;
    }

    hb_log_info("journal: started");

    uint64_t last_check = hb_mono_sec();

    while (ctx->running) {
        // Re-open journal if filters changed (best-effort).
        uint64_t now = hb_mono_sec();
        if (now - last_check >= 5) {
            uint32_t next_sig = 0;
            char next_ids[32][64];
            size_t next_n = hb_filters_get_syslog_identifiers(ctx, (char *)next_ids, 32, sizeof(next_ids[0]), &next_sig);
            if (next_sig != sig) {
                sd_journal *next = NULL;
                if (open_and_match(&next, next_ids, next_n) == 0) {
                    sd_journal_close(j);
                    j = next;
                    sig = next_sig;
                    hb_log_info("journal: match set updated");
                }
            }
            last_check = now;
        }

        int r = sd_journal_wait(j, 1000 * 1000);
        if (r < 0) {
            if (!ctx->running) break;
            usleep(100000);
            continue;
        }
        if (r == SD_JOURNAL_NOP) continue;

        while (ctx->running && sd_journal_next(j) > 0) {
            if (!(ctx->cfg.flags & (1u << 5))) continue; // journal disabled

            char syslog_id[64] = {0};
            (void)get_field_value(j, "SYSLOG_IDENTIFIER", syslog_id, sizeof(syslog_id));

            char msg[1024] = {0};
            if (get_field_value(j, "MESSAGE", msg, sizeof(msg)) != 0) continue;

            char filter_name[64];
            char ip[128];
            if (!hb_filters_match(ctx, syslog_id, msg, filter_name, sizeof(filter_name), ip, sizeof(ip))) continue;

            hb_detection_on_filter_fail(ctx, filter_name, ip);
        }
    }

    sd_journal_close(j);
    hb_log_info("journal: stopped");
    return NULL;
}

#endif

int hb_journal_start(hb_ctx *ctx) {
    if (!ctx) return -1;
    if (!(ctx->cfg.flags & (1u << 5))) {
        hb_log_info("journal: disabled by config");
        return 0;
    }
#ifndef HONEYBAN_WITH_SYSTEMD
    hb_log_info("journal: libsystemd unavailable, using file backend");
    if (pthread_create(&ctx->journal_thread, NULL, file_thread, ctx) != 0) {
        hb_log_error("logtail: thread create failed");
        return -1;
    }
    return 0;
#else
    if (pthread_create(&ctx->journal_thread, NULL, journal_thread, ctx) != 0) {
        hb_log_error("journal: thread create failed");
        return -1;
    }
    return 0;
#endif
}

void hb_journal_stop(hb_ctx *ctx) { (void)ctx; }
