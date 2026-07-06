package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractShellAssignment: `var=value` is an assignment (no `$` on LHS, no
// spaces around `=`); a `$1` on the RHS is a positional-parameter source read.
func TestExtractShellAssignment(t *testing.T) {
	src := []byte("host=$1\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "")
	if len(u.stmts) == 0 {
		t.Fatalf("no statements extracted: %+v", units)
	}
	st := u.stmts[0]
	if st.assigns != "host" {
		t.Fatalf("assigns = %q, want host", st.assigns)
	}
	if !containsStr(st.calls, "$1") && !containsStr(st.chains, "$1") {
		t.Errorf("RHS should surface the $1 source; calls=%v chains=%v", st.calls, st.chains)
	}
}

// TestExtractShellCommandCallee: a paren-less command `eval "$x"` is recognized
// as a call to `eval` reading x.
func TestExtractShellCommandCallee(t *testing.T) {
	src := []byte("input=$1\neval \"$input\"\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "eval")
	if sink.line == 0 {
		t.Fatalf("eval call not recognized: %+v", u.stmts)
	}
	if !containsStr(sink.reads, "input") {
		t.Errorf("eval reads = %v, want to include input", sink.reads)
	}
}

// TestExtractShellFunctionUnit: both `f() {` and `function f {` open a unit.
func TestExtractShellFunctionUnit(t *testing.T) {
	src := []byte("deploy() {\n  x=$1\n  eval \"$x\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "deploy")
	if u.funcName != "deploy" {
		t.Fatalf("expected deploy unit, got %+v", units)
	}
	if stmtWithCall(t, u, "eval").line == 0 {
		t.Errorf("eval not recognized inside function body")
	}
}

func TestExtractShellFunctionKeywordForm(t *testing.T) {
	src := []byte("function run {\n  eval \"$1\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "run")
	if u.funcName != "run" {
		t.Fatalf("expected run unit, got %+v", units)
	}
}

// TestExtractShellReadSource: `read foo` taints foo (the var it reads into).
func TestExtractShellReadSource(t *testing.T) {
	src := []byte("read foo\neval \"$foo\"\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "")
	var readStmt stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "foo" {
			readStmt = u.stmts[i]
		}
	}
	if readStmt.assigns != "foo" {
		t.Fatalf("read foo should assign foo; stmts=%+v", u.stmts)
	}
	if !containsStr(readStmt.calls, "read") && !containsStr(readStmt.chains, "read") {
		t.Errorf("read foo should surface the read source; calls=%v", readStmt.calls)
	}
}

// TestExtractShellBraceExpansionRead: `${var}` reads are variable reads.
func TestExtractShellBraceExpansionRead(t *testing.T) {
	src := []byte("input=$1\ncmd=\"run ${input}\"\neval \"$cmd\"\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "cmd" {
			assign = u.stmts[i]
		}
	}
	if !containsStr(assign.reads, "input") {
		t.Errorf("cmd assignment should read input via ${input}; reads=%v", assign.reads)
	}
}

// TestExtractShellSpecialParamSources: $@, $*, $# are positional sources.
func TestExtractShellSpecialParamSources(t *testing.T) {
	src := []byte("all=$@\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "")
	st := u.stmts[0]
	if !containsStr(st.calls, "$@") && !containsStr(st.chains, "$@") {
		t.Errorf("$@ should surface as a source; calls=%v chains=%v", st.calls, st.chains)
	}
}
