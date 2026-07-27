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

// TestExtractShellLocalAssignmentIsTainted: `local x="$1"` is a declaration AND
// an assignment. Skipping the whole line as scaffolding meant the declared
// variable was never tainted, so a downstream `eval "$x"` was missed — the
// suite's tp_known_fns.sh false negative. The declaration keyword is blanked and
// the assignment underneath is recognized normally.
func TestExtractShellLocalAssignmentIsTainted(t *testing.T) {
	src := []byte("launder() {\n  local arg=\"$1\"\n  eval \"$arg\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "launder")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "arg" {
			assign = u.stmts[i]
		}
	}
	if assign.assigns != "arg" {
		t.Fatalf("`local arg=\"$1\"` did not yield an assignment to arg: %+v", u.stmts)
	}
	if !containsStr(assign.calls, "$1") && !containsStr(assign.chains, "$1") {
		t.Errorf("local assignment should surface the $1 source; calls=%v chains=%v",
			assign.calls, assign.chains)
	}
	sink := stmtWithCall(t, u, "eval")
	if !containsStr(sink.reads, "arg") {
		t.Errorf("eval reads = %v, want to include arg", sink.reads)
	}
}

// TestExtractShellDeclWithFlagsIsAssignment: the declaration builtins take
// option flags (`local -r`, `declare -i`), which sit between the keyword and the
// assignment and must not stop it being recognized.
func TestExtractShellDeclWithFlagsIsAssignment(t *testing.T) {
	for _, src := range []string{
		"f() {\n  local -r arg=\"$1\"\n  eval \"$arg\"\n}\n",
		"f() {\n  declare -i arg=\"$1\"\n  eval \"$arg\"\n}\n",
		"f() {\n  readonly arg=\"$1\"\n  eval \"$arg\"\n}\n",
		"f() {\n  export arg=\"$1\"\n  eval \"$arg\"\n}\n",
	} {
		units := extractUnits(lexctx.LangShell, []byte(src))
		u := findUnit(t, units, "f")
		found := false
		for i := range u.stmts {
			if u.stmts[i].assigns == "arg" {
				found = true
			}
		}
		if !found {
			t.Errorf("no assignment to arg for %q: %+v", src, u.stmts)
		}
	}
}

// TestExtractShellBareDeclarationStaysStructural is the precision guard. A
// declaration with NO assignment (`local a b c`, `declare -A map`) carries no
// dataflow and must stay scaffolding — reading it as a command would invent a
// call to `local`/`declare` and could attribute a sink to it.
func TestExtractShellBareDeclarationStaysStructural(t *testing.T) {
	src := []byte("f() {\n  local a b c\n  declare -A map\n  local count\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "f")
	for _, st := range u.stmts {
		if st.assigns != "" {
			t.Errorf("bare declaration produced an assignment to %q: %+v", st.assigns, st)
		}
		for _, c := range st.calls {
			if c == "local" || c == "declare" {
				t.Errorf("bare declaration read as a call to %q: %+v", c, st)
			}
		}
	}
}

// TestExtractShellTrailingBackslashInQuotedWord is a crash regression. The
// double-quote scanner treated a backslash as escaping the NEXT byte without
// checking one existed, so a word ending in a lone backslash advanced the index
// past the end of the line — panicking the scanner as soon as anything sliced
// the raw view by that index. A security scanner must never crash on input it is
// pointed at.
func TestExtractShellTrailingBackslashInQuotedWord(t *testing.T) {
	for _, src := range []string{
		"f \"a\\\\\n",
		"cmd \"x\\\\\n",
		"eval \"$v\\\\\n",
		"a=\"b\\\\\n",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on %q: %v", src, r)
				}
			}()
			extractUnits(lexctx.LangShell, []byte(src))
		}()
	}
}

// TestExtractShellExecRedirectionIsNotACommand: `exec 200>"$f"` rebinds the
// shell's own file descriptors and executes nothing, so a tainted path there is
// not command injection. Only `exec CMD ...` is the sink.
func TestExtractShellExecRedirectionIsNotACommand(t *testing.T) {
	src := []byte("f() {\n  local lock=\"$1\"\n  exec 200>\"$lock\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "f")
	for _, st := range u.stmts {
		if containsStr(st.calls, "exec") {
			t.Errorf("exec redirection recognized as a command call: %+v", st)
		}
	}
}

// TestExtractShellHyphenatedCommandIsNotExec: a user-defined `exec-add-path` is
// its own command. Scanning the name only up to the hyphen truncated it to
// `exec`, an exact-match command-injection sink, so every tainted argument to
// any `exec-*` helper was reported as CWE-78.
func TestExtractShellHyphenatedCommandIsNotExec(t *testing.T) {
	src := []byte("f() {\n  local formula=\"$1\"\n  exec-add-path \"/opt/${formula}/bin\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "f")
	for _, st := range u.stmts {
		if containsStr(st.calls, "exec") {
			t.Errorf("exec-add-path truncated to the exec sink: %+v", st)
		}
	}
}

// TestExtractShellPathQualifiedCommandResolves: the catalog is keyed on bare
// command names, so a path-qualified invocation must normalize to its final
// segment or the sink is lost.
func TestExtractShellPathQualifiedCommandResolves(t *testing.T) {
	src := []byte("f() {\n  local u=\"$1\"\n  /usr/bin/curl \"$u\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "f")
	if sink := stmtWithCall(t, u, "curl"); sink.line == 0 {
		t.Errorf("/usr/bin/curl did not resolve to the curl sink: %+v", u.stmts)
	}
}

// TestExtractShellFetchOutputFlagIsNotTheURL: `curl --output "$path" "$url"`
// writes $path and fetches $url. A tainted $path controls where the file lands,
// not which host is contacted, so it must not be reported as the SSRF-carrying
// argument. The URL argument still is.
func TestExtractShellFetchOutputFlagIsNotTheURL(t *testing.T) {
	src := []byte("f() {\n  local out=\"$1\"\n  curl --output \"$out\" \"https://example.com/x\"\n}\n")
	units := extractUnits(lexctx.LangShell, src)
	u := findUnit(t, units, "f")
	sink := stmtWithCall(t, u, "curl")
	if sink.line == 0 {
		t.Fatalf("curl call not recognized: %+v", u.stmts)
	}
	if containsStr(sink.sinkArgs["curl"].taintedArgVars, "out") {
		t.Errorf("--output argument treated as the SSRF URL: %+v", sink.sinkArgs["curl"])
	}

	// The URL argument must still count.
	src2 := []byte("f() {\n  local u=\"$1\"\n  curl --output /tmp/x \"$u\"\n}\n")
	units2 := extractUnits(lexctx.LangShell, src2)
	u2 := findUnit(t, units2, "f")
	sink2 := stmtWithCall(t, u2, "curl")
	if !containsStr(sink2.sinkArgs["curl"].taintedArgVars, "u") {
		t.Errorf("tainted URL argument lost: %+v", sink2.sinkArgs["curl"])
	}
}
