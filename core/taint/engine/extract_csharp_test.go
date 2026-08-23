package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// stmtWithChain returns the first statement in u whose chains include chain — for
// locating ATTRIBUTE sources (Request.QueryString), which are read as dotted
// chains rather than calls.
func stmtWithChain(t *testing.T, u unitDraft, chain string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		for _, c := range u.stmts[i].chains {
			if c == chain {
				return u.stmts[i]
			}
		}
	}
	t.Fatalf("no statement with chain %q in unit %q", chain, u.funcName)
	return stmtDraft{}
}

// TestExtractCSharpAssignmentAndCall covers the core shape: a `var lhs = source`
// assignment, then a bare sink call reading the tainted variable, both inside a
// method whose parameters are recognized.
func TestExtractCSharpAssignmentAndCall(t *testing.T) {
	src := []byte(`using System.Diagnostics;

public class Handler
{
    public void Run(HttpRequest Request)
    {
        var name = Request.QueryString["report"];
        Process.Start("cmd.exe", "/c gen " + name);
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "Run")

	// The method parameter is recognized (Request).
	if !containsStr(u.params, "Request") {
		t.Errorf("params = %v, want to include Request", u.params)
	}

	// Request.QueryString[...] is an ATTRIBUTE source (bracket index), captured as
	// a chain rather than a call. Locate the assignment by its LHS name.
	assign := stmtWithChain(t, u, "Request.QueryString")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name", assign.assigns)
	}

	sink := stmtWithCall(t, u, "Process.Start")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractCSharpAttributeSource covers an ATTRIBUTE source (Request.QueryString
// with a bracket index) captured as a chain so the engine can taint from it.
func TestExtractCSharpAttributeSource(t *testing.T) {
	src := []byte(`public class C
{
    void M(HttpRequest Request)
    {
        var q = Request.QueryString["id"];
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "M")
	if len(u.stmts) == 0 {
		t.Fatalf("no statements extracted: %+v", u)
	}
	st := u.stmts[0]
	if st.assigns != "q" {
		t.Errorf("assign LHS = %q, want q", st.assigns)
	}
	if !containsStr(st.chains, "Request.QueryString") {
		t.Errorf("chains = %v, want to include Request.QueryString", st.chains)
	}
}

// TestExtractCSharpTypedDeclaration covers a `Type lhs = rhs` declaration (not
// `var`): the declared type is stripped and the bare LHS name is recognized.
func TestExtractCSharpTypedDeclaration(t *testing.T) {
	src := []byte(`public class C
{
    void M(HttpRequest Request)
    {
        string user = Request.Form["u"];
        SqlCommand cmd = new SqlCommand("SELECT * FROM t WHERE x='" + user + "'");
        cmd.ExecuteReader();
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "M")

	decl := stmtWithChain(t, u, "Request.Form")
	if decl.assigns != "user" {
		t.Errorf("typed decl LHS = %q, want user", decl.assigns)
	}
	// SqlCommand construction reads the tainted `user` (concatenated into SQL).
	ctor := stmtWithCall(t, u, "SqlCommand")
	if !containsStr(ctor.reads, "user") {
		t.Errorf("SqlCommand reads = %v, want to include user", ctor.reads)
	}
}

// TestExtractCSharpReturnStatement covers a `return sink(...)` line: the return
// carries the sink call and reads the tainted variable.
func TestExtractCSharpReturnStatement(t *testing.T) {
	src := []byte(`public class C
{
    string M(HttpRequest Request)
    {
        var id = Request.QueryString["id"];
        return File.ReadAllText(id);
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "M")
	sink := stmtWithCall(t, u, "File.ReadAllText")
	if !containsStr(sink.reads, "id") {
		t.Errorf("File.ReadAllText reads = %v, want to include id", sink.reads)
	}
	if len(sink.returns) == 0 || !containsStr(sink.returns, "id") {
		t.Errorf("return statement returns = %v, want to include id", sink.returns)
	}
}

// TestExtractCSharpIgnoresStringsAndComments: Process.Start appears in a comment
// and a string; neither must be extracted. Only the real call counts.
func TestExtractCSharpIgnoresStringsAndComments(t *testing.T) {
	src := []byte(`public class C
{
    void M()
    {
        // Process.Start("evil") is dangerous
        var note = "call Process.Start(x) here";
        Process.Start(real);
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "M")
	count := 0
	for _, s := range u.stmts {
		for _, c := range s.calls {
			if c == "Process.Start" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("Process.Start extracted %d times, want 1 (comment+string ignored)", count)
	}
}

// TestExtractCSharpMultiLineCall: a call spanning physical lines is one logical
// statement and its argument read is captured.
func TestExtractCSharpMultiLineCall(t *testing.T) {
	src := []byte(`public class C
{
    void M(HttpRequest Request)
    {
        var q = Request.QueryString["id"];
        Process.Start(
            "cmd",
            q
        );
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "M")
	sink := stmtWithCall(t, u, "Process.Start")
	if !containsStr(sink.reads, "q") {
		t.Errorf("multi-line sink reads = %v, want to include q", sink.reads)
	}
}

// TestExtractCSharpMethodHeaderNotACall pins that a method header is not read as
// a data-flow call to the method name.
func TestExtractCSharpMethodHeaderNotACall(t *testing.T) {
	src := []byte(`public class C
{
    public void Configure(string input)
    {
        var x = 1;
    }
}
`)
	units := extractUnits(lexctx.LangCSharp, src)
	u := findUnit(t, units, "Configure")
	for _, s := range u.stmts {
		if containsStr(s.calls, "Configure") {
			t.Errorf("method header wrongly read as a call to Configure: %+v", s)
		}
	}
	if !containsStr(u.params, "input") {
		t.Errorf("params = %v, want to include input", u.params)
	}
}

// topLevelAssignIndex must find only a genuine top-level assignment, skipping
// comparison and COMPOUND-assignment operators. The compound set was missing,
// so `x += y` used to return the `=` inside `+=` and split into a bogus LHS.
func TestTopLevelAssignIndex(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"plain assignment", "x = getInput()", 2},
		{"no assignment", "doThing(a, b)", -1},
		{"equality is not assignment", "if a == b", -1},
		{"compound += is not a plain assignment", "total += getInput()", -1},
		{"compound -= ", "n -= 1", -1},
		{"compound *= ", "n *= 2", -1},
		{"compound |= ", "flags |= X", -1},
		{"assignment inside brackets is not top-level", "call(a = b)", -1},
		{"generic type args do not confuse the scan", "Map<K, V> m = make()", 12},
		{"greater-equal is not assignment", "x >= y", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := topLevelAssignIndex(tt.in); got != tt.want {
				t.Errorf("topLevelAssignIndex(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
