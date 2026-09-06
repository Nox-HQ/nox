package engine

import "testing"

// jq's @sh filter shell-quotes every value it emits: it wraps the value in
// single quotes and escapes embedded single quotes as '\”. So the canonical
// JSON-to-shell idiom below is safe, and nox reported it as TAINT-005 high —
// twice in one real deployment script.
//
// Verified by injection rather than by reading the docs: a payload of
//
//	'; touch /tmp/PWNED; echo '
//
// arrives at `set --` as a literal string and the command does not run. That
// matters because Kubernetes NAMES are RFC-1123-restricted, but the label
// values and annotations these scripts read are not — @sh is doing real work
// here, not decoration.
func TestAtShQuotedPipelineDoesNotReachEval(t *testing.T) {
	src := "kubectl get svc -o json | jq -r '.items[] | \"\\(.metadata.name | @sh)\"' | while read -r row; do\n" +
		"  eval \"set -- $row\"\n" +
		"done\n"
	if flows := analyzeShell(t, src); len(flows) != 0 {
		t.Errorf("@sh-quoted pipeline should not reach eval; got %v", flows)
	}
}

// The bar is `jq` AND `@sh`, never the callee alone. Without the @sh the values
// are raw and the eval is a real code-injection sink.
func TestJqWithoutAtShStillReachesEval(t *testing.T) {
	src := "kubectl get svc -o json | jq -r '.items[].metadata.name' | while read -r row; do\n" +
		"  eval \"set -- $row\"\n" +
		"done\n"
	flows := analyzeShell(t, src)
	if !shellHasRule(flows, "TAINT-005") {
		t.Errorf("jq without @sh must still report TAINT-005; got %v", flows)
	}
}

// The upstream check must not generalise to "any sanitizer in the pipeline".
//
// `printf` is in the shell sanitizer catalog for `printf %q`, but the entry
// matches the CALL and not the format string. Honouring it in the pipeline
// position would make this look sanitized while it quotes nothing at all —
// converting a coarse entry that currently costs false positives into one that
// costs false NEGATIVES, which is the direction that hides real injections.
func TestPrintfPipedToReadIsNotTreatedAsQuoting(t *testing.T) {
	src := "printf '%s\\n' \"$UNSAFE\" | while read -r row; do\n" +
		"  eval \"set -- $row\"\n" +
		"done\n"
	flows := analyzeShell(t, src)
	if !shellHasRule(flows, "TAINT-005") {
		t.Errorf("printf upstream must not clear the eval sink; got %v", flows)
	}
}

// A read with no quoting producer upstream is unchanged.
func TestPlainReadStillReachesEval(t *testing.T) {
	for _, src := range []string{
		"read -r row\neval \"set -- $row\"\n",
		"cat /tmp/data | while read -r row; do\n  eval \"set -- $row\"\ndone\n",
	} {
		flows := analyzeShell(t, src)
		if !shellHasRule(flows, "TAINT-005") {
			t.Errorf("plain read must still report TAINT-005 for %q; got %v", src, flows)
		}
	}
}

// The clearing is CLASS-PRECISE, and this is the test that keeps it honest.
//
// @sh makes a value safe to re-parse as shell syntax. It does not make the
// value trustworthy. A shell-quoted URL is still an attacker's URL, and a
// shell-quoted path is still an attacker's path — curl's own catalog note says
// SSRF applies "regardless of quoting". Both must still fire.
func TestAtShClearsOnlyTheShellParsingClasses(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"ssrf survives @sh", "  curl \"$row\"\n", "TAINT-006"},
		{"path traversal survives @sh", "  source \"$row\"\n", "TAINT-004"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := "kubectl get svc -o json | jq -r '.items[] | (.v | @sh)' | while read -r row; do\n" +
				tc.body + "done\n"
			flows := analyzeShell(t, src)
			if !shellHasRule(flows, tc.want) {
				t.Errorf("%s must still fire; got %v", tc.want, flows)
			}
		})
	}
}
