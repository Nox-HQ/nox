// Format string (CWE-134): a user-controlled string is passed as the FORMAT
// argument of printf. An attacker-supplied `%n`/`%s` in that string reads or
// writes arbitrary memory. The bug is the TAINTED FORMAT — printf(user) — not a
// tainted value with a fixed format. nox maps CWE-134 to the TAINT-005 rule id
// (no dedicated CWE-134 class) and gates the sink on the first argument (the
// format) being tainted, so printf("%s", user) stays clean.
#include <stdio.h>
#include <stdlib.h>

void log_message(void) {
    char *user = getenv("MESSAGE");
    printf(user); // nox-expect: TAINT-005
}
