package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// analyzeFile is the interprocedural end-to-end helper: source bytes → units →
// cross-function flows, using the default embedded catalog. It exercises the
// same-file function-summary propagation that the intraprocedural analyze helper
// deliberately does not.
func analyzeFile(t *testing.T, lang lexctx.Lang, src string) []taint.Flow {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t"+extFor(lang), lang, []byte(src))
	return eng.AnalyzeFile(units)
}

// flowWithIntermediate reports whether some flow names fn in its Via path.
func flowWithIntermediate(flows []taint.Flow, fn string) bool {
	for i := range flows {
		for _, v := range flows[i].Via {
			if v == fn {
				return true
			}
		}
	}
	return false
}

func TestInterprocSinksArgTruePositive(t *testing.T) {
	// The canonical cross-function command injection: the sink lives in a helper,
	// the tainted value is produced in the caller and handed to the helper.
	src := `def run(c):
    os.system(c)

def handler():
    cmd = request.args.get("x")
    run(cmd)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("cross-function command injection not detected: %+v", ruleIDs(flows))
	}
	if !flowWithIntermediate(flows, "run") {
		t.Fatalf("flow does not name the intermediate helper 'run': %+v", flows)
	}
}

func TestInterprocReturnsTaintedTruePositive(t *testing.T) {
	// x = wrap(source()); sink(x) where wrap returns its argument unchanged.
	src := `def wrap(v):
    return v

def handler():
    x = wrap(request.args.get("x"))
    os.system(x)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("return-taint propagation across wrap() not detected: %+v", ruleIDs(flows))
	}
}

func TestInterprocReturnsTaintedFromTaintedLocal(t *testing.T) {
	// The source is assigned to a local first, then handed to wrap; the returned
	// value must remain tainted.
	src := `def wrap(v):
    return v

def handler():
    raw = request.args.get("x")
    x = wrap(raw)
    os.system(x)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("return-taint across wrap(local) not detected: %+v", ruleIDs(flows))
	}
}

func TestInterprocTwoFunctionChain(t *testing.T) {
	// A two-hop chain: handler → wrap (returns tainted) → run (sinks it). Requires
	// iterating the summary fixpoint so run's summary and wrap's summary compose.
	src := `def run(c):
    os.system(c)

def wrap(v):
    return v

def handler():
    cmd = request.args.get("x")
    y = wrap(cmd)
    run(y)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("two-function chain not detected: %+v", ruleIDs(flows))
	}
	if !flowWithIntermediate(flows, "run") {
		t.Fatalf("two-function chain flow does not name 'run': %+v", flows)
	}
}

func TestInterprocSanitizedInHelperNoFire(t *testing.T) {
	// The helper sanitizes its argument before the sink: no finding, even though
	// the caller passes tainted data.
	src := `def run(c):
    os.system(shlex.quote(c))

def handler():
    cmd = request.args.get("x")
    run(cmd)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if hasRule(flows, "TAINT-002") {
		t.Fatalf("sanitized-in-helper flow wrongly fired: %+v", ruleIDs(flows))
	}
}

func TestInterprocNoSourceNoFire(t *testing.T) {
	// The helper sinks its argument, but the caller passes a constant: no taint,
	// no finding.
	src := `def run(c):
    os.system(c)

def handler():
    run("ls -la")
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if len(flows) != 0 {
		t.Fatalf("no-source cross-function call fired: %+v", ruleIDs(flows))
	}
}

func TestInterprocRecursionNoCrash(t *testing.T) {
	// Direct and mutual recursion must terminate (bounded fixpoint) and never
	// crash. We assert only that AnalyzeFile returns; correctness of the flow (if
	// any) is secondary to fail-safe termination.
	src := `def loop(x):
    return loop(x)

def ping(x):
    return pong(x)

def pong(x):
    return ping(x)

def handler():
    cmd = request.args.get("x")
    y = loop(cmd)
    os.system(y)
`
	// Must not hang or panic.
	_ = analyzeFile(t, lexctx.LangPython, src)
}

func TestInterprocUnknownCalleeNoFalsePositive(t *testing.T) {
	// A call to a callee not defined in this file is not a local function; its
	// summary is unknown, so we must NOT invent a sink or propagate taint through
	// it (fail safe: no false positive).
	src := `def handler():
    cmd = request.args.get("x")
    y = external_lib.process(cmd)
    log(y)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if len(flows) != 0 {
		t.Fatalf("unknown callee produced a false positive: %+v", ruleIDs(flows))
	}
}

func TestInterprocDeterministic(t *testing.T) {
	src := `def run(c):
    os.system(c)

def wrap(v):
    return v

def handler():
    cmd = request.args.get("x")
    y = wrap(cmd)
    run(y)
`
	first := analyzeFile(t, lexctx.LangPython, src)
	for i := 0; i < 8; i++ {
		got := analyzeFile(t, lexctx.LangPython, src)
		if len(got) != len(first) {
			t.Fatalf("nondeterministic flow count at run %d: %d vs %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].SinkLine != first[j].SinkLine || got[j].SinkCall != first[j].SinkCall {
				t.Fatalf("nondeterministic output at run %d", i)
			}
		}
	}
}

func TestInterprocDoesNotDoubleReportIntraprocedural(t *testing.T) {
	// A purely intraprocedural flow (source and sink in the same function) must be
	// reported exactly once by AnalyzeFile, not duplicated by the interprocedural
	// pass.
	src := `def handler():
    cmd = request.args.get("x")
    os.system(cmd)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	n := 0
	for i := range flows {
		if flows[i].Sink.RuleID == "TAINT-002" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("intraprocedural flow reported %d times, want 1: %+v", n, flows)
	}
}

func TestInterprocLaunderReturnsConstant(t *testing.T) {
	// wrap ignores its arg and returns a constant: the returned value is NOT
	// tainted, so os.system must not fire. This proves a non-taint-returning local
	// helper is a taint BARRIER — the raw argument read must not leak through it.
	src := `def wrap(v):
    return "safe-constant"

def handler():
    cmd = request.args.get("x")
    x = wrap(cmd)
    os.system(x)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if hasRule(flows, "TAINT-002") {
		t.Fatalf("laundered (constant-return) value wrongly fired: %+v", ruleIDs(flows))
	}
}

func TestInterprocKeywordArgNoBind(t *testing.T) {
	// The tainted value is passed as a keyword argument; positional binding does
	// not apply, so we neither fabricate a cross-function flow nor crash.
	src := `def run(c):
    os.system(c)

def handler():
    cmd = request.args.get("x")
    run(c=cmd)
`
	_ = analyzeFile(t, lexctx.LangPython, src)
}

func TestInterprocParamSinksArgClassPrecise(t *testing.T) {
	// A helper that sinks its arg into an XSS sink must not fire for a value that
	// was command-sanitized but not XSS-sanitized, and vice-versa. Here we assert
	// the summary carries the sink's vuln class through: the cross-function flow
	// keeps the helper sink's rule ID.
	src := `def render(name):
    mark_safe(name)

def handler():
    n = request.args.get("n")
    render(n)
`
	flows := analyzeFile(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-003") { // TAINT-003 is XSS in the catalog
		t.Fatalf("cross-function XSS flow not detected with correct rule ID: %+v", ruleIDs(flows))
	}
}
