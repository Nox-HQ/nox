// Clean: the user-controlled path is canonicalized with realpath() and the
// result is refused unless it lies under the allowed base. realpath alone is not
// a defence — it RESOLVES `../../etc/shadow`, it does not refuse it — so the
// base-prefix check is what makes the fopen safe, and a correct scanner emits
// nothing only because both are present.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define REPORT_BASE "/var/reports/"

FILE *open_report(void) {
    char *path = getenv("REPORT_PATH");
    char resolved[PATH_MAX];
    char *safe = realpath(path, resolved); // canonicalizes away ../ traversal
    if (safe == NULL || strncmp(safe, REPORT_BASE, strlen(REPORT_BASE)) != 0) {
        return NULL;
    }
    return fopen(safe, "r");
}
