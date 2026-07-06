package engine

import (
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
