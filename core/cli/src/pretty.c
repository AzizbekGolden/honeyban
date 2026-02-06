// SPDX-License-Identifier: MIT

#include "honeyban_cli.h"

#include <stdio.h>
#include <string.h>

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

void hb_pretty_print_kv(const char *json) {
    const char *p = json;
    while (*p && *p != '{') p++;
    if (*p != '{') {
        printf("%s\n", json);
        return;
    }
    p++;

    while (*p) {
        p = skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == '}') break;
        if (*p != '"') break;
        p++;
        const char *k0 = p;
        while (*p && *p != '"') p++;
        if (*p != '"') break;
        int klen = (int)(p - k0);
        p++;
        p = skip_ws(p);
        if (*p != ':') break;
        p++;
        p = skip_ws(p);

        printf("%.*s=", klen, k0);

        if (*p == '"') {
            p++;
            const char *v0 = p;
            while (*p && *p != '"') p++;
            if (*p != '"') break;
            printf("%.*s\n", (int)(p - v0), v0);
            p++;
            continue;
        }

        const char *v0 = p;
        while (*p && *p != ',' && *p != '}') p++;
        int vlen = (int)(p - v0);
        while (vlen > 0 && (v0[vlen - 1] == ' ' || v0[vlen - 1] == '\t')) vlen--;
        printf("%.*s\n", vlen, v0);
    }
}

