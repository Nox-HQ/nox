// Clean: every dangerous call operates on a CONSTANT, not on untrusted input.
// The path, command, and format are all string literals, so there is no taint
// source and nothing to report. A correct scanner emits nothing; any finding
// here is a false positive from matching a sink call without a real source.
#include <stdio.h>
#include <stdlib.h>

void startup(void) {
    FILE *cfg = fopen("/etc/app/config.ini", "r");
    if (cfg) {
        fclose(cfg);
    }
    system("systemctl reload app");
    printf("startup complete\n");
}
