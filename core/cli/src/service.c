// SPDX-License-Identifier: MIT

#include "honeyban_cli.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int has_systemctl(void) {
    return access("/bin/systemctl", X_OK) == 0 || access("/usr/bin/systemctl", X_OK) == 0;
}

int hb_service_exec(int argc, char **argv) {
    if (!has_systemctl()) {
        fprintf(stderr, "error: systemctl not found\n");
        return 1;
    }

    // Pass-through: honeyban service <args...> -> systemctl <args...> honeyban
    if (argc < 2) {
        fprintf(stderr, "error: service requires a subcommand (status|start|stop|restart|enable|disable|logs)\n");
        return 2;
    }

    const char *sub = argv[1];
    const char *unit = "honeyban.service";

    if (!strcmp(sub, "logs")) {
        char *args[] = {"journalctl", "-u", (char *)unit, "-n", "200", "--no-pager", NULL};
        execvp(args[0], args);
        fprintf(stderr, "error: exec journalctl: %s\n", strerror(errno));
        return 1;
    }

    char *args[] = {"systemctl", (char *)sub, (char *)unit, NULL};
    execvp(args[0], args);
    fprintf(stderr, "error: exec systemctl: %s\n", strerror(errno));
    return 1;
}

