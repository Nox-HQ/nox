package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeCPPFile runs the full same-file pipeline (extraction + interprocedural
// AnalyzeFile) over C/C++ source, mirroring how taintflow drives the engine.
func analyzeCPPFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.cpp", lexctx.LangCPP, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

// TestStructuralCPPTruePositives pins the injection classes the C/C++ taint model
// is designed to catch. Memory-safety bugs are intentionally out of scope (see
// the suite README) and are NOT asserted here.
func TestStructuralCPPTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via system(getenv)",
			src: `void run(void) {
    char *name = getenv("REPORT");
    system(name);
}`,
			wantID: "TAINT-002",
		},
		{
			name: "command injection via popen",
			src: `void run(void) {
    char *cmd = getenv("CMD");
    FILE *p = popen(cmd, "r");
}`,
			wantID: "TAINT-002",
		},
		{
			name: "path traversal via fopen(getenv)",
			src: `void serve(void) {
    char *path = getenv("FILE");
    FILE *f = fopen(path, "r");
}`,
			wantID: "TAINT-004",
		},
		{
			name: "format string via printf(user)",
			src: `void log_it(void) {
    char *user = getenv("MSG");
    printf(user);
}`,
			wantID: "TAINT-005",
		},
		{
			name: "sql injection via mysql_query",
			src: `void lookup(MYSQL *db) {
    char *id = getenv("ID");
    mysql_query(db, id);
}`,
			wantID: "TAINT-001",
		},
		{
			name: "ssrf via curl_easy_setopt url",
			src: `void fetch(CURL *h) {
    char *url = getenv("URL");
    curl_easy_setopt(h, CURLOPT_URL, url);
}`,
			wantID: "TAINT-006",
		},
		{
			// Canonical C command-injection: taint from getenv flows into cmd via the
			// strcat out-parameter builder, then into system.
			name: "command injection via system(strcat(cmd, getenv))",
			src: `void run(void) {
    char *arg = getenv("ARG");
    char cmd[256];
    strcpy(cmd, "tool ");
    strcat(cmd, arg);
    system(cmd);
}`,
			wantID: "TAINT-002",
		},
		{
			// Buffer-writing input source: fgets writes untrusted bytes into buf,
			// which flows into system.
			name: "command injection via system(fgets buffer)",
			src: `void run(void) {
    char buf[128];
    fgets(buf, sizeof(buf), stdin);
    system(buf);
}`,
			wantID: "TAINT-002",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeCPPFile(t, tt.src)
			if !containsStr(ids, tt.wantID) {
				t.Errorf("flows = %v, want to include %s", ids, tt.wantID)
			}
		})
	}
}

// TestStructuralCPPCleanNoFlow pins the precision guardrails: safe usages must
// emit NOTHING. The headline case is the format-string shape — printf("%s", user)
// (fixed format, tainted VALUE) is SAFE, distinct from printf(user) (tainted
// format) which is the vuln.
func TestStructuralCPPCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "fixed-format printf with tainted value is safe",
			src: `void log_it(void) {
    char *user = getenv("MSG");
    printf("%s", user);
}`,
		},
		{
			name: "atoi numeric coercion defuses command injection",
			src: `void run(void) {
    char *raw = getenv("N");
    int n = atoi(raw);
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "job %d", n);
    system(cmd);
}`,
		},
		{
			name: "no source: constant path fopen",
			src: `void serve(void) {
    FILE *f = fopen("/etc/config", "r");
}`,
		},
		{
			name: "realpath sanitizes traversal",
			src: `void serve(void) {
    char *path = getenv("FILE");
    char resolved[4096];
    char *safe = realpath(path, resolved);
    FILE *f = fopen(safe, "r");
}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeCPPFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("clean sample fired %v, want no flows", ids)
			}
		})
	}
}
