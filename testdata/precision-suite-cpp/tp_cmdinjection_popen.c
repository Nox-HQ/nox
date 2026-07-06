// Command injection via popen: a user-controlled tool name read from stdin with
// fgets is interpolated into a shell pipeline opened by popen(3). popen runs its
// argument through the shell exactly like system, so a tainted command string is
// CWE-78. A correct scanner fires TAINT-002.
#include <stdio.h>
#include <string.h>

void run_tool(void) {
    char tool[128];
    fgets(tool, sizeof(tool), stdin);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "run-%s --once", tool);
    FILE *pipe = popen(cmd, "r"); // nox-expect: TAINT-002
    if (pipe) {
        pclose(pipe);
    }
}
