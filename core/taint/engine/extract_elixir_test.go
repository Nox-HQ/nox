package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractElixirDefParamsAndCall pins the core recognizer shapes for Elixir: a
// `def name(a, b) do` header with positional params, an assignment, and a call
// that reads the assigned variable.
func TestExtractElixirDefParamsAndCall(t *testing.T) {
	src := []byte(`def handle(conn, opts) do
  cmd = conn.params["cmd"]
  System.cmd("sh", ["-c", cmd])
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "conn" || u.params[1] != "opts" {
		t.Fatalf("params = %v, want [conn opts]", u.params)
	}
	sink := stmtWithCall(t, u, "System.cmd")
	found := false
	for _, r := range sink.reads {
		if r == "cmd" {
			found = true
		}
	}
	if !found {
		t.Errorf("System.cmd stmt reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractElixirDefp verifies a private `defp` header also opens a unit.
func TestExtractElixirDefp(t *testing.T) {
	src := []byte(`defp run(cmd) do
  :os.cmd(cmd)
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "run")
	if len(u.params) != 1 || u.params[0] != "cmd" {
		t.Fatalf("params = %v, want [cmd]", u.params)
	}
}

// TestExtractElixirPatternMatchAssign: a `lhs = rhs` pattern-match binds the LHS
// variable and surfaces the RHS reads.
func TestExtractElixirPatternMatchAssign(t *testing.T) {
	src := []byte(`def handle(conn) do
  q = conn.query_params
  x = q
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "q" {
			assign = u.stmts[i]
		}
	}
	if assign.assigns != "q" {
		t.Fatalf("no assignment to q found: %+v", u.stmts)
	}
	// `conn.query_params` must surface as a chain so resolveSource matches.
	sawChain := false
	for _, c := range assign.chains {
		if c == "conn.query_params" {
			sawChain = true
		}
	}
	if !sawChain {
		t.Errorf("assign chains = %v, want to include conn.query_params", assign.chains)
	}
}

// TestExtractElixirPipe: the pipe operator `x |> f()` means x is the first
// argument to f. A tainted value piped into a sink must surface as a read of the
// sink call.
func TestExtractElixirPipe(t *testing.T) {
	src := []byte(`def handle(conn) do
  cmd = conn.params["cmd"]
  cmd |> System.cmd([])
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	sink := stmtWithCall(t, u, "System.cmd")
	if sink.line == 0 {
		t.Fatalf("piped System.cmd call not recognized: %+v", u.stmts)
	}
	found := false
	for _, r := range sink.reads {
		if r == "cmd" {
			found = true
		}
	}
	if !found {
		t.Errorf("piped System.cmd reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractElixirMultiStagePipe: a value piped through TWO-plus stages
// (`x |> f() |> g()`) must reach the final sink, not just the first stage.
// Desugaring peels one pipe per rewrite (`a |> f() |> g()` → `f(a) |> g()`), so
// the rewrite has to run to fixpoint; stopping after one stage leaves the sink
// holding no argument and loses the flow. This is the elixir suite's documented
// `run_piped/1` false negative.
func TestExtractElixirMultiStagePipe(t *testing.T) {
	// The source expression is piped INLINE, with no intermediate binding — the
	// exact shape of the suite's run_piped/1 sample. A bound variable would leak a
	// line-level read and mask the gap.
	src := []byte(`def handle(conn) do
  conn.params["cmd"] |> String.trim() |> :os.cmd()
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	sink := stmtWithCall(t, u, "os.cmd")
	if sink.line == 0 {
		t.Fatalf("final pipe stage os.cmd not recognized: %+v", u.stmts)
	}
	found := false
	for _, c := range sink.chains {
		if strings.Contains(c, "conn.params") {
			found = true
		}
	}
	if !found {
		t.Errorf("multi-stage piped os.cmd chains = %v, want to include conn.params", sink.chains)
	}
}

// TestExtractElixirThreeStagePipe: the fixpoint rewrite must not stop at two —
// an arbitrary-length chain lands the value in the final sink.
func TestExtractElixirThreeStagePipe(t *testing.T) {
	src := []byte(`def handle(conn) do
  conn.params["cmd"] |> String.trim() |> String.downcase() |> :os.cmd()
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	sink := stmtWithCall(t, u, "os.cmd")
	if sink.line == 0 {
		t.Fatalf("final pipe stage os.cmd not recognized: %+v", u.stmts)
	}
	found := false
	for _, c := range sink.chains {
		if strings.Contains(c, "conn.params") {
			found = true
		}
	}
	if !found {
		t.Errorf("three-stage piped os.cmd chains = %v, want to include conn.params", sink.chains)
	}
}

// TestExtractElixirParenlessCall: a paren-less call (`IO.puts x`) is recognized
// as a call to IO.puts.
func TestExtractElixirParenlessCall(t *testing.T) {
	src := []byte(`def handle(conn) do
  data = conn.body_params
  IO.puts data
end
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "handle")
	sink := stmtWithCall(t, u, "IO.puts")
	if sink.line == 0 {
		t.Fatalf("paren-less IO.puts call not recognized: %+v", u.stmts)
	}
}

// TestExtractElixirModuleUnit: top-level code (outside any def) folds into the
// module unit.
func TestExtractElixirModuleUnit(t *testing.T) {
	src := []byte(`x = System.get_env("PATH")
Code.eval_string(x)
`)
	units := extractUnits(lexctx.LangElixir, src)
	u := findUnit(t, units, "")
	if len(u.stmts) < 2 {
		t.Fatalf("module unit stmts = %d, want >= 2: %+v", len(u.stmts), u.stmts)
	}
	sink := stmtWithCall(t, u, "Code.eval_string")
	if sink.line == 0 {
		t.Fatalf("Code.eval_string not recognized in module unit: %+v", u.stmts)
	}
}

// TestElixirDestructuredNames: a destructuring pattern-match binds names the
// single-assignee model cannot express, so the extracted variable never carried
// the RHS's taint.
func TestElixirDestructuredNames(t *testing.T) {
	for _, tc := range []struct {
		code string
		want []string
	}{
		{`%{      => path} = conn.params`, []string{"path"}},
		{`%{query: q} = conn`, []string{"q"}},
		{`{:ok, body} = fetch()`, []string{"body"}},
		{`[head | tail] = list`, []string{"head", "tail"}},
		// Not a destructuring bind: the ordinary assignment path handles it, so
		// nothing must be doubled here.
		{`x = conn.params`, nil},
		{`conn.params`, nil},
		{`a == b`, nil},
	} {
		got := elixirDestructuredNames(tc.code)
		if len(got) != len(tc.want) {
			t.Errorf("names(%q) = %v, want %v", tc.code, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("names(%q) = %v, want %v", tc.code, got, tc.want)
				break
			}
		}
	}
}
