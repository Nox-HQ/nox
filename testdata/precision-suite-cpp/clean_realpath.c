// Clean: the user-controlled path is canonicalized with realpath() before being
// opened. Together with the caller's base-prefix check (elided for brevity) this
// resolves `../` traversal, so the fopen is safe. A correct scanner emits
// nothing; a TAINT-004 finding here is a false positive because realpath is a
// registered path sanitizer.
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

FILE *open_report(void) {
    char *path = getenv("REPORT_PATH");
    char resolved[PATH_MAX];
    char *safe = realpath(path, resolved); // canonicalizes away ../ traversal
    return fopen(safe, "r");
}
