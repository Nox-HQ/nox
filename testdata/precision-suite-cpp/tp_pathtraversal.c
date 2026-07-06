// Path traversal: a user-controlled path read from the environment is passed
// straight to fopen(3) with no realpath canonicalization or base-prefix check,
// so `../../etc/passwd` escapes the intended directory. This is CWE-22. A correct
// scanner fires TAINT-004.
#include <stdio.h>
#include <stdlib.h>

FILE *open_report(void) {
    char *path = getenv("REPORT_PATH");
    FILE *f = fopen(path, "r"); // nox-expect: TAINT-004
    return f;
}
