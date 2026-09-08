package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

func analyzeSuppressions(t *testing.T, path, src string) ([]taint.Flow, []taint.Suppression) {
	t.Helper()
	cat := taint.MustDefault()
	e := NewStructuralEngine(cat)
	units := ExtractUnits(path, lexctx.LangFromPath(path), []byte(src))
	return e.AnalyzeFileWithSuppressions(units)
}

// A sanitizer that clears a value is recorded as a refutation.
//
// The engine performs the most sophisticated refinement in nox and recorded
// none of it: the stage accounting reported TAINT as refuting nothing on every
// corpus, which was true of the ledger and false of the engine. A sanitizer
// recognizer that clears the WRONG thing produces a result indistinguishable
// from one that had nothing to clear — both show no finding — and nox has
// shipped that defect more than once.
func TestASanitizedFlowIsRecordedAsRefuted(t *testing.T) {
	src := `import subprocess, shlex
from flask import request

def run():
    cmd = shlex.quote(request.args.get("c"))
    subprocess.call(cmd, shell=True)
`
	flows, suppressed := analyzeSuppressions(t, "app.py", src)
	if len(flows) != 0 {
		t.Fatalf("a shlex.quote-ed value reached a shell sink as a finding: %+v", flows)
	}
	if len(suppressed) == 0 {
		t.Fatal("the sanitizer cleared the flow and recorded nothing; the decision is " +
			"invisible, which is the state this exists to end")
	}
	s := suppressed[0]
	if s.Reason == "" {
		t.Error("a suppression with no reason is a bare continue with extra steps")
	}
	if s.Class == "" {
		t.Error("no class: a sanitizer clears one class and not others, so which one is " +
			"part of the claim")
	}
	if s.RuleID == "" {
		t.Error("no rule ID, so the suppression cannot be attributed to a family")
	}
}

// The distinction that the refutation-hard corpus taught, pinned.
//
// An argument SHAPE that is not dangerous — an argv exec, a parameterized query
// — says this CALL is safe. It says nothing about the VALUE, which is untouched
// and just as tainted. A sanitizer says the opposite: an operation ran on the
// value, and that travels with it.
//
// Recording the first as a refutation conflates them, and
// h2_dynamic_dispatch.go is what it costs: an argv `exec.Command("echo", s)` on
// one line, an `sh -c` on another, and the choice made by data the engine
// cannot follow. Refuting the first reads as resolving the file.
func TestAnUndangerousCallShapeIsNotARefutation(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func handle(r *http.Request) error {
	cmd := r.URL.Query().Get("cmd")
	return exec.Command("echo", cmd).Run()
}
`
	flows, suppressed := analyzeSuppressions(t, "main.go", src)
	if len(flows) != 0 {
		t.Fatalf("an argv exec was reported as a shell injection: %+v", flows)
	}
	for _, s := range suppressed {
		if strings.Contains(s.Reason, "shape") || strings.Contains(s.Reason, "spawns no shell") {
			t.Errorf("the argument shape was recorded as a refutation: %q. It establishes "+
				"that this CALL is safe, not that the VALUE is — and the value flows on "+
				"untouched.", s.Reason)
		}
	}
}

// An un-sanitized flow is still a finding. Without this, "records refutations"
// is satisfiable by refuting everything.
func TestAnUnsanitizedFlowStillReports(t *testing.T) {
	src := `import subprocess
from flask import request

def run():
    cmd = request.args.get("c")
    subprocess.call(cmd, shell=True)
`
	flows, _ := analyzeSuppressions(t, "app.py", src)
	if len(flows) == 0 {
		t.Error("an un-sanitized value reaching a shell sink produced no finding; the " +
			"suppression path is swallowing real flows")
	}
}

// Suppressions are deterministically ordered: they reach the artifact through
// the stage accounting, and findings.json is byte-identical across runs.
func TestSuppressionsAreDeterministic(t *testing.T) {
	src := `import subprocess, shlex
from flask import request

def a():
    subprocess.call(shlex.quote(request.args.get("x")), shell=True)

def b():
    subprocess.call(shlex.quote(request.args.get("y")), shell=True)
`
	var first string
	for i := 0; i < 6; i++ {
		_, ss := analyzeSuppressions(t, "app.py", src)
		var b strings.Builder
		for _, s := range ss {
			b.WriteString(s.FilePath + s.SinkCall + s.Class + s.SourceVar + "|")
		}
		if i == 0 {
			first = b.String()
			continue
		}
		if b.String() != first {
			t.Fatalf("run %d ordered suppressions differently", i+1)
		}
	}
}
