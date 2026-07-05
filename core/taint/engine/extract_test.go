package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// findUnit returns the unit whose FuncName matches name, or the module unit when
// name is "" — a small helper so tests read declaratively.
func findUnit(t *testing.T, units []unitDraft, name string) unitDraft {
	t.Helper()
	for _, u := range units {
		if u.funcName == name {
			return u
		}
	}
	t.Fatalf("no unit named %q (have %d units)", name, len(units))
	return unitDraft{}
}

// stmtWithCall returns the first statement in u that invokes call.
func stmtWithCall(t *testing.T, u unitDraft, call string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		for _, c := range u.stmts[i].calls {
			if c == call {
				return u.stmts[i]
			}
		}
	}
	t.Fatalf("no statement calling %q in unit %q", call, u.funcName)
	return stmtDraft{}
}

func TestExtractPythonAssignmentAndCall(t *testing.T) {
	src := []byte(`import os

def handle():
    q = request.args.get("id")
    os.system(q)
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "handle")
	if len(u.stmts) < 2 {
		t.Fatalf("want >=2 stmts, got %d: %+v", len(u.stmts), u.stmts)
	}

	assign := stmtWithCall(t, u, "request.args.get")
	if assign.assigns != "q" {
		t.Errorf("assign LHS = %q, want q", assign.assigns)
	}

	sink := stmtWithCall(t, u, "os.system")
	found := false
	for _, r := range sink.reads {
		if r == "q" {
			found = true
		}
	}
	if !found {
		t.Errorf("sink stmt reads = %v, want to include q", sink.reads)
	}
}

func TestExtractDottedCallNormalization(t *testing.T) {
	src := []byte(`def f():
    p = flask.request.args.get("c")
    cursor.execute("SELECT " + p)
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "f")
	// The extractor stores the full chain; the engine resolves it to the catalog
	// via suffix fallback (verified separately). Here we confirm the chain is
	// captured and that its suffix keys include the catalog form.
	s := stmtWithCall(t, u, "flask.request.args.get")
	if s.assigns != "p" {
		t.Errorf("dotted call not found or wrong LHS: %+v", s)
	}
	if !containsStr(suffixKeys("flask.request.args.get"), "request.args.get") {
		t.Errorf("suffixKeys missing catalog form: %v", suffixKeys("flask.request.args.get"))
	}
	if s := stmtWithCall(t, u, "cursor.execute"); len(s.reads) == 0 {
		t.Errorf("cursor.execute stmt has no reads: %+v", s)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestExtractIgnoresStringsAndComments(t *testing.T) {
	// os.system appears in a comment and a string; neither must be extracted as
	// a call. Only the real one at the bottom counts.
	src := []byte(`def f():
    # os.system("rm -rf /") is dangerous
    note = "call os.system(x) here"
    os.system(real)
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "f")
	count := 0
	for _, s := range u.stmts {
		for _, c := range s.calls {
			if c == "os.system" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("os.system extracted %d times, want 1 (comment+string must be ignored)", count)
	}
}

func TestExtractMultiLineCall(t *testing.T) {
	src := []byte(`def f():
    q = request.args.get("id")
    os.system(
        q
    )
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "f")
	sink := stmtWithCall(t, u, "os.system")
	found := false
	for _, r := range sink.reads {
		if r == "q" {
			found = true
		}
	}
	if !found {
		t.Errorf("multi-line sink reads = %v, want q", sink.reads)
	}
}

func TestExtractShellTrueDetected(t *testing.T) {
	src := []byte(`def f():
    cmd = request.args.get("c")
    subprocess.run(cmd, shell=True)
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "f")
	s := stmtWithCall(t, u, "subprocess.run")
	info, ok := s.sinkArgs["subprocess.run"]
	if !ok {
		t.Fatalf("no sink-arg info for subprocess.run: %+v", s)
	}
	if !info.shellTrue {
		t.Errorf("shell=True not detected: %+v", info)
	}
}

func TestExtractParameterizedExecuteHasTwoArgs(t *testing.T) {
	src := []byte(`def f():
    user = request.args.get("u")
    cursor.execute("SELECT * FROM t WHERE x = %s", (user,))
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "f")
	s := stmtWithCall(t, u, "cursor.execute")
	info := s.sinkArgs["cursor.execute"]
	if info.argCount < 2 {
		t.Errorf("argCount = %d, want >=2 for parameterized call", info.argCount)
	}
	if info.firstArgTainted {
		t.Errorf("firstArgTainted = true, want false (taint is only in the params tuple)")
	}
}

func TestExtractModuleLevelUnit(t *testing.T) {
	src := []byte(`q = request.args.get("id")
os.system(q)
`)
	units := extractUnits(lexctx.LangPython, src)
	u := findUnit(t, units, "")
	if len(u.stmts) < 2 {
		t.Fatalf("module unit has %d stmts, want >=2", len(u.stmts))
	}
}
