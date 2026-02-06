// SPDX-License-Identifier: MIT

#include "ini.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

int hb_ini_parse_file(const char *path, hb_ini_kv_fn on_kv, void *userdata) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char section[64] = {0};
    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == '\0') continue;
        if (*p == '#' || *p == ';') continue;

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) continue;
            *end = '\0';
            strncpy(section, trim(p + 1), sizeof(section) - 1);
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = trim(p);
        char *v = trim(eq + 1);
        if (*k == '\0') continue;
        if (on_kv) on_kv(userdata, section, k, v);
    }

    fclose(fp);
    return 0;
}

