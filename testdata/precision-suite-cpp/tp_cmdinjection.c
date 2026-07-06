// Command injection: an environment variable (standing in for any untrusted
// input) is concatenated into a shell command with strcat and handed to
// system(3), which runs it through /bin/sh -c. There is no allow-list and no
// escaping, so a value like `; rm -rf /` executes. This is CWE-78. A correct
// scanner fires TAINT-002; nox's C/C++ taint model matches the tainted value
// flowing into the system() call.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_report(void) {
    char *name = getenv("REPORT");
    char cmd[256];
    strcpy(cmd, "generate-report ");
    strcat(cmd, name);
    system(cmd); // nox-expect: TAINT-002
}
