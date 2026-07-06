// Clean: the user-controlled value is passed as a VALUE argument to printf with a
// FIXED format literal ("%s"). This is the correct, safe way to print untrusted
// text — the format string is not attacker-controlled, so there is no CWE-134.
// A correct scanner emits nothing; a TAINT-005 finding here is a false positive.
// This is the headline precision guardrail for the C/C++ format-string sink.
#include <stdio.h>
#include <stdlib.h>

void log_message(void) {
    char *user = getenv("MESSAGE");
    printf("%s\n", user); // safe: fixed format, tainted value only
    fprintf(stderr, "user said: %s\n", user);
}
