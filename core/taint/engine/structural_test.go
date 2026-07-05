package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// analyze is the end-to-end helper: source bytes → units → flows, using the
// default embedded catalog. It is what the table tests assert against.
func analyze(t *testing.T, lang lexctx.Lang, src string) []taint.Flow {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t"+extFor(lang), lang, []byte(src))
	var flows []taint.Flow
	for i := range units {
		flows = append(flows, eng.Analyze(units[i])...)
	}
	return flows
}

func extFor(lang lexctx.Lang) string {
	if lang == lexctx.LangJavaScript {
		return ".js"
	}
	return ".py"
}

// ruleIDs returns the sorted rule IDs of the flows, for compact assertions.
func ruleIDs(flows []taint.Flow) []string {
	var out []string
	for i := range flows {
		out = append(out, flows[i].Sink.RuleID)
	}
	sortStrings(out)
	return out
}

func hasRule(flows []taint.Flow, id string) bool {
	for i := range flows {
		if flows[i].Sink.RuleID == id {
			return true
		}
	}
	return false
}

func TestStructuralPythonTruePositives(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantIDs []string // exact set of rule IDs expected to fire
	}{
		{
			name: "sqli via concat",
			src: `def h():
    q = request.args.get("id")
    cursor.execute("SELECT * FROM t WHERE id = " + q)
`,
			wantIDs: []string{"TAINT-001"},
		},
		{
			name: "command injection",
			src: `def h():
    cmd = flask.request.args.get("c")
    os.system(cmd)
`,
			wantIDs: []string{"TAINT-002"},
		},
		{
			name: "two-hop assignment chain",
			src: `def h():
    a = request.args.get("x")
    b = a
    os.system(b)
`,
			wantIDs: []string{"TAINT-002"},
		},
		{
			name: "subprocess shell=True with tainted cmd",
			src: `def h():
    cmd = request.args.get("c")
    subprocess.run(cmd, shell=True)
`,
			wantIDs: []string{"TAINT-002"},
		},
		{
			name: "env var into eval",
			src: `def h():
    code = os.getenv("EXPR")
    eval(code)
`,
			wantIDs: []string{"TAINT-005"},
		},
		{
			name: "f-string style concat into cursor.execute",
			src: `def h():
    name = request.form.get("n")
    sql = "SELECT * FROM u WHERE n = '" + name + "'"
    cursor.execute(sql)
`,
			wantIDs: []string{"TAINT-001"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flows := analyze(t, lexctx.LangPython, tc.src)
			got := ruleIDs(flows)
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("rule IDs = %v, want %v", got, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if got[i] != tc.wantIDs[i] {
					t.Fatalf("rule IDs = %v, want %v", got, tc.wantIDs)
				}
			}
		})
	}
}

func TestStructuralPythonSanitizedNoFire(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "shlex.quote before os.system",
			src: `def h():
    user = request.args.get("c")
    safe = shlex.quote(user)
    os.system(safe)
`,
		},
		{
			name: "parameterized cursor.execute",
			src: `def h():
    user = request.args.get("u")
    cursor.execute("SELECT * FROM t WHERE x = %s", (user,))
`,
		},
		{
			name: "subprocess.run without shell (arg vector)",
			src: `def h():
    cmd = request.args.get("c")
    subprocess.run(["ls", cmd])
`,
		},
		{
			name: "html.escape defuses xss sink",
			src: `def h():
    name = request.args.get("n")
    safe = html.escape(name)
    mark_safe(safe)
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if flows := analyze(t, lexctx.LangPython, tc.src); len(flows) != 0 {
				t.Fatalf("expected no flows, got %d: %+v", len(flows), ruleIDs(flows))
			}
		})
	}
}

func TestStructuralPythonNoSourceNoFire(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "constant command",
			src: `def h():
    os.system("ls -la")
`,
		},
		{
			name: "local constant into sink",
			src: `def h():
    cmd = "echo hi"
    os.system(cmd)
`,
		},
		{
			name: "source assigned but never reaches sink",
			src: `def h():
    q = request.args.get("id")
    log(q)
    os.system("static")
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if flows := analyze(t, lexctx.LangPython, tc.src); len(flows) != 0 {
				t.Fatalf("expected no flows, got %d: %+v", len(flows), ruleIDs(flows))
			}
		})
	}
}

func TestStructuralWrongClassSanitizerStillFires(t *testing.T) {
	// html.escape defuses XSS, not command injection: a value escaped for HTML
	// then passed to os.system must still fire. This proves class-precise
	// sanitization (the whole point of the VulnClass join).
	src := `def h():
    user = request.args.get("c")
    safe = html.escape(user)
    os.system(safe)
`
	flows := analyze(t, lexctx.LangPython, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("wrong-class sanitizer suppressed a real command-injection flow: %+v", ruleIDs(flows))
	}
}

func TestStructuralJavaScriptCommandInjection(t *testing.T) {
	src := `function h(req) {
    const cmd = req.query;
    child_process.exec(cmd);
}
`
	flows := analyze(t, lexctx.LangJavaScript, src)
	if !hasRule(flows, "TAINT-002") {
		t.Fatalf("JS command injection not detected: %+v", ruleIDs(flows))
	}
}

func TestStructuralDeterministicOrder(t *testing.T) {
	src := `def h():
    q = request.args.get("id")
    os.system(q)
    eval(q)
`
	first := analyze(t, lexctx.LangPython, src)
	if len(first) != 2 {
		t.Fatalf("want 2 flows, got %d", len(first))
	}
	for i := 0; i < 5; i++ {
		got := analyze(t, lexctx.LangPython, src)
		for j := range got {
			if got[j].SinkLine != first[j].SinkLine || got[j].SinkCall != first[j].SinkCall {
				t.Fatalf("nondeterministic output at run %d", i)
			}
		}
	}
	if first[0].SinkLine > first[1].SinkLine {
		t.Fatalf("flows not sorted by sink line")
	}
}
