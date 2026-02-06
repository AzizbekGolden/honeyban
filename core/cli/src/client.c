// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include "honeyban_cli.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int connect_unix(const char *path, int timeout_sec) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path) >= (int)sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static ssize_t read_line(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (ssize_t)i;
}

int hb_client_request(const hb_client_opts *opts, const char *req_json, char *resp, size_t resp_cap) {
    const char *path = (opts && opts->socket_path) ? opts->socket_path : HONEYBAN_DEFAULT_SOCKET;
    int timeout_sec = (opts && opts->timeout_sec > 0) ? opts->timeout_sec : HONEYBAN_DEFAULT_TIMEOUT_SEC;

    int fd = connect_unix(path, timeout_sec);
    if (fd < 0) return -1;

    if (write_all(fd, req_json, strlen(req_json)) < 0 || write_all(fd, "\n", 1) < 0) {
        close(fd);
        return -1;
    }

    ssize_t n = read_line(fd, resp, resp_cap);
    close(fd);
    if (n < 0) return -1;
    if (n == 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

