// Clean: the user-controlled value is coerced to a typed integer with atoi()
// before being built into a shell command. Numeric coercion removes every
// injection metacharacter, so no command injection is possible even though the
// value flows into system(). A correct scanner emits nothing; a TAINT-002 finding
// here is a false positive.
#include <stdio.h>
#include <stdlib.h>

void run_job(void) {
    char *raw = getenv("JOB_ID");
    int id = atoi(raw); // numeric coercion — id cannot carry a shell payload
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "run-job %d", id);
    system(cmd);
}
