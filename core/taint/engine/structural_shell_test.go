package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeShell is the end-to-end helper for shell: source → units → flows.
func analyzeShell(t *testing.T, src string) []taintFlowIDs {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.sh", lexctx.LangShell, []byte(src))
	flows := eng.AnalyzeFile(units)
	out := make([]taintFlowIDs, 0, len(flows))
	for i := range flows {
		out = append(out, taintFlowIDs{rule: flows[i].Sink.RuleID, class: string(flows[i].Sink.VulnClass)})
	}
	return out
}

func shellHasRule(flows []taintFlowIDs, id string) bool {
	for _, f := range flows {
		if f.rule == id {
			return true
		}
	}
	return false
}

// TestStructuralShellTruePositives exercises the headline shell injection
// classes end to end, asserting the expected rule ID fires.
func TestStructuralShellTruePositives(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "code injection via eval of $1",
			src:  "input=$1\neval \"$input\"\n",
			want: "TAINT-005",
		},
		{
			name: "command injection via bash -c of positional param",
			src:  "user=$1\nbash -c \"$user\"\n",
			want: "TAINT-002",
		},
		{
			name: "command injection via sh -c",
			src:  "cmd=$2\nsh -c \"$cmd\"\n",
			want: "TAINT-002",
		},
		{
			name: "path traversal via source of a tainted path",
			src:  "cfg=$1\nsource \"$cfg\"\n",
			want: "TAINT-004",
		},
		{
			name: "ssrf via curl of a tainted url",
			src:  "url=$1\ncurl \"$url\"\n",
			want: "TAINT-006",
		},
		{
			name: "ssrf via wget of a tainted url (unquoted)",
			src:  "u=$1\nwget $u\n",
			want: "TAINT-006",
		},
		{
			name: "read source into eval",
			src:  "read target\neval \"$target\"\n",
			want: "TAINT-005",
		},
		{
			name: "CGI QUERY_STRING into eval",
			src:  "q=$QUERY_STRING\neval \"$q\"\n",
			want: "TAINT-005",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeShell(t, tt.src)
			if !shellHasRule(flows, tt.want) {
				t.Errorf("expected %s to fire; got flows=%v\nsrc:\n%s", tt.want, flows, tt.src)
			}
		})
	}
}

// TestStructuralShellCleanNoFalsePositives pins the precision guardrail: safe
// shell idioms must NOT fire. This is the hard part for shell.
func TestStructuralShellCleanNoFalsePositives(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "quoted expansion to a non-sink command",
			src:  "src=$1\ncp \"$src\" /backup/\n",
		},
		{
			name: "bash running a static script (no -c)",
			src:  "bash /opt/deploy.sh\n",
		},
		{
			name: "constant command is never tainted",
			src:  "eval \"echo hello\"\n",
		},
		{
			name: "printf %q sanitizes before eval",
			src:  "raw=$1\nsafe=$(printf %q \"$raw\")\neval \"$safe\"\n",
		},
		{
			name: "basename defuses path traversal before source",
			src:  "p=$1\nbase=$(basename \"$p\")\nsource \"/etc/app/$base\"\n",
		},
		{
			name: "no source: local static assignment into eval",
			src:  "x=constant\neval \"$x\"\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeShell(t, tt.src)
			if len(flows) != 0 {
				t.Errorf("expected no findings, got %v\nsrc:\n%s", flows, tt.src)
			}
		})
	}
}
