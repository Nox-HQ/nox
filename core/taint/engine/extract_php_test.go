package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractPHPFunctionParams pins the function-header recognizer: a
// `function name($a, $b)` header opens a unit. PHP normalization strips the `$`
// sigil uniformly (from params AND from every variable read/assign in the body),
// so the internal IR uses bare identifiers — self-consistent, so a param `req`
// matches a read `req`.
func TestExtractPHPFunctionParams(t *testing.T) {
	src := []byte("<?php\nfunction handle($req, $db) {\n  $x = 1;\n}\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "req" || u.params[1] != "db" {
		t.Errorf("params = %v, want [req db]", u.params)
	}
}

// TestExtractPHPSuperglobalSource covers a superglobal array-index source read:
// `$cmd = $_GET['cmd'];` must record `_GET` as a source chain so the engine
// resolves it as a source, tainting cmd.
func TestExtractPHPSuperglobalSource(t *testing.T) {
	src := []byte("<?php\n$cmd = $_GET['cmd'];\nsystem($cmd);\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "")

	var srcStmt *stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "cmd" {
			srcStmt = &u.stmts[i]
		}
	}
	if srcStmt == nil {
		t.Fatalf("no assignment to cmd; stmts=%+v", u.stmts)
	}
	if !containsStr(srcStmt.chains, "_GET") {
		t.Errorf("cmd assignment source chains = %v, want to include _GET", srcStmt.chains)
	}
}

// TestExtractPHPBareCallSink: a bare `system($cmd);` records the callee `system`
// and reads cmd.
func TestExtractPHPBareCallSink(t *testing.T) {
	src := []byte("<?php\n$cmd = $_GET['cmd'];\nsystem($cmd);\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "system")
	if !containsStr(sink.reads, "cmd") {
		t.Errorf("system reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractPHPMethodCallNormalized covers `$pdo->query("… " . $id)`: the
// method call must normalize `$pdo->query` to the dotted chain `pdo.query` so the
// catalog's method-suffix key matches, with id recorded as a read.
func TestExtractPHPMethodCallNormalized(t *testing.T) {
	src := []byte("<?php\n$id = $_GET['id'];\n$pdo->query(\"SELECT * FROM t WHERE id = \" . $id);\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "pdo.query")
	if !containsStr(sink.reads, "id") {
		t.Errorf("pdo.query reads = %v, want to include id", sink.reads)
	}
}

// TestExtractPHPEchoStatement covers the `echo $x;` construct — echo is a
// language construct, not a call with parens, so the recognizer must still model
// it as a sink call `echo` reading name.
func TestExtractPHPEchoStatement(t *testing.T) {
	src := []byte("<?php\n$name = $_GET['name'];\necho $name;\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "echo")
	if !containsStr(sink.reads, "name") {
		t.Errorf("echo reads = %v, want to include name", sink.reads)
	}
}

// TestExtractPHPReturnStatement covers `return $pdo->query(... . $id);` — the
// return must carry the sink call and read the tainted variable.
func TestExtractPHPReturnStatement(t *testing.T) {
	src := []byte("<?php\nfunction q($pdo, $id) {\n  return $pdo->query(\"SELECT \" . $id);\n}\n")
	units := extractUnits(lexctx.LangPHP, src)
	u := findUnit(t, units, "q")
	sink := stmtWithCall(t, u, "pdo.query")
	if !containsStr(sink.reads, "id") {
		t.Errorf("pdo.query reads = %v, want to include id", sink.reads)
	}
}
