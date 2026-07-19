package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeRuleIDs runs the full same-file pipeline (extraction + interprocedural
// AnalyzeFile) and returns the sorted rule IDs — the shape these recall tests
// assert against.
func analyzeRuleIDs(t *testing.T, path string, lang lexctx.Lang, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits(path, lang, []byte(src))
	return ruleIDs(eng.AnalyzeFile(units))
}

// These tests pin the five confirmed recall holes closed. DISCIPLINE: every fix
// carries a POSITIVE case (the flow is now detected) AND a NEGATIVE case (the same
// flow, sanitized, must NOT fire — the engine's existing sanitizers must not be
// bypassed by the recall fix). A recall fix that flags a sanitized value is a
// precision regression, which the precision bench guards globally.

// --- F1: a source used DIRECTLY as a sink argument in one statement ---

func TestRecallF1_SourceDirectlyAsSinkArg(t *testing.T) {
	pos := []struct {
		name string
		path string
		lang lexctx.Lang
		src  string
		want string
	}{
		{"py os.system(request.args.get())", "t.py", lexctx.LangPython,
			"def h():\n    os.system(request.args.get('c'))\n", "TAINT-002"},
		{"js child_process.exec(req.query)", "t.js", lexctx.LangJavaScript,
			"function h(req) {\n    child_process.exec(req.query);\n}\n", "TAINT-002"},
		{"php system($_GET)", "t.php", lexctx.LangPHP,
			"<?php\nsystem($_GET['c']);\n", "TAINT-002"},
		{"go exec.Command(r.FormValue())", "t.go", lexctx.LangGo,
			"package p\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\nfunc h(r *http.Request) {\n\texec.Command(r.FormValue(\"c\"))\n}\n", "TAINT-002"},
	}
	for _, tc := range pos {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			if ids := analyzeRuleIDs(t, tc.path, tc.lang, tc.src); !containsStr(ids, tc.want) {
				t.Fatalf("want %s detected, got %v", tc.want, ids)
			}
		})
	}

	neg := []struct {
		name string
		path string
		lang lexctx.Lang
		src  string
	}{
		// A sanitizer wrapping the inline source at the call site must suppress it.
		{"py shlex.quote wraps inline source", "t.py", lexctx.LangPython,
			"def h():\n    os.system(shlex.quote(request.args.get('c')))\n"},
		{"js parseInt wraps inline source", "t.js", lexctx.LangJavaScript,
			"function h(req) {\n    child_process.exec(parseInt(req.query));\n}\n"},
		{"php escapeshellarg wraps inline source", "t.php", lexctx.LangPHP,
			"<?php\nsystem(escapeshellarg($_GET['c']));\n"},
		{"go strconv.Atoi wraps inline source", "t.go", lexctx.LangGo,
			"package p\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n\t\"strconv\"\n)\nfunc h(r *http.Request) {\n\texec.Command(strconv.Atoi(r.FormValue(\"c\")))\n}\n"},
	}
	for _, tc := range neg {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			if ids := analyzeRuleIDs(t, tc.path, tc.lang, tc.src); len(ids) != 0 {
				t.Fatalf("sanitized inline source must not fire, got %v", ids)
			}
		})
	}
}

// --- F2: attribute-source + trailing accessor (prefix-aware source matching) ---

func TestRecallF2_AttributeSourceAccessor(t *testing.T) {
	pos := []struct {
		name string
		path string
		lang lexctx.Lang
		src  string
		want string
	}{
		{"js req.query.<param>", "t.js", lexctx.LangJavaScript,
			"function h(req) {\n    const id = req.query.id;\n    child_process.exec(id);\n}\n", "TAINT-002"},
		{"js req.body.<field>", "t.js", lexctx.LangJavaScript,
			"function h(req) {\n    const n = req.body.name;\n    child_process.exec(n);\n}\n", "TAINT-002"},
		{"py request.values.get", "t.py", lexctx.LangPython,
			"def h():\n    c = request.values.get('c')\n    os.system(c)\n", "TAINT-002"},
		{"py request.cookies.get", "t.py", lexctx.LangPython,
			"def h():\n    c = request.cookies.get('c')\n    os.system(c)\n", "TAINT-002"},
	}
	for _, tc := range pos {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			if ids := analyzeRuleIDs(t, tc.path, tc.lang, tc.src); !containsStr(ids, tc.want) {
				t.Fatalf("want %s detected, got %v", tc.want, ids)
			}
		})
	}

	neg := []struct {
		name string
		path string
		lang lexctx.Lang
		src  string
	}{
		{"js sanitized req.query.id", "t.js", lexctx.LangJavaScript,
			"function h(req) {\n    const id = req.query.id;\n    const safe = parseInt(id);\n    child_process.exec(safe);\n}\n"},
		{"py sanitized request.values.get", "t.py", lexctx.LangPython,
			"def h():\n    c = request.values.get('c')\n    safe = shlex.quote(c)\n    os.system(safe)\n"},
	}
	for _, tc := range neg {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			if ids := analyzeRuleIDs(t, tc.path, tc.lang, tc.src); len(ids) != 0 {
				t.Fatalf("sanitized accessor source must not fire, got %v", ids)
			}
		})
	}
}

// --- F3: PHP string-concatenation sink arguments ---

func TestRecallF3_PHPConcatSinkArg(t *testing.T) {
	t.Run("positive/system concat", func(t *testing.T) {
		src := "<?php\n$id = $_GET['id'];\nsystem('ls '.$id);\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); !containsStr(ids, "TAINT-002") {
			t.Fatalf("want TAINT-002, got %v", ids)
		}
	})
	t.Run("positive/mysqli_query concat", func(t *testing.T) {
		src := "<?php\n$id = $_GET['id'];\nmysqli_query($c, 'SELECT '.$id);\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); !containsStr(ids, "TAINT-001") {
			t.Fatalf("want TAINT-001, got %v", ids)
		}
	})
	t.Run("negative/escapeshellarg in concat", func(t *testing.T) {
		src := "<?php\n$id = $_GET['id'];\n$s = escapeshellarg($id);\nsystem('ls '.$s);\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); len(ids) != 0 {
			t.Fatalf("sanitized concat must not fire, got %v", ids)
		}
	})
	t.Run("negative/decimal literal is not concat", func(t *testing.T) {
		// A decimal point in a number must not be treated as a concat/read; nothing
		// tainted, nothing fires.
		src := "<?php\n$rate = 1.5;\nsystem('sleep 1');\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); len(ids) != 0 {
			t.Fatalf("decimal literal must not fire, got %v", ids)
		}
	})
}

// --- F4: PHP brace-on-header-line (same-line) function bodies ---

func TestRecallF4_PHPSameLineBody(t *testing.T) {
	t.Run("positive/inline body reached via helper", func(t *testing.T) {
		// The task's exact illustration: the helper body is on the header line.
		src := "<?php\nfunction run($c){ system($c); }\nrun($_GET['c']);\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); !containsStr(ids, "TAINT-002") {
			t.Fatalf("want TAINT-002, got %v", ids)
		}
	})
	t.Run("positive/inline body parity with multi-line", func(t *testing.T) {
		inline := "<?php\nfunction run($c){ system($c); }\n$v = $_GET['c'];\nrun($v);\n"
		multi := "<?php\nfunction run($c){\n  system($c);\n}\n$v = $_GET['c'];\nrun($v);\n"
		gotInline := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, inline)
		gotMulti := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, multi)
		if !containsStr(gotInline, "TAINT-002") {
			t.Fatalf("inline-body form missed the flow: %v", gotInline)
		}
		if len(gotInline) != len(gotMulti) {
			t.Fatalf("inline body must match multi-line: inline=%v multi=%v", gotInline, gotMulti)
		}
	})
	t.Run("positive/source and sink both in inline body", func(t *testing.T) {
		src := "<?php\nfunction run(){ $x = $_GET['c']; system($x); }\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); !containsStr(ids, "TAINT-002") {
			t.Fatalf("want TAINT-002, got %v", ids)
		}
	})
	t.Run("negative/sanitized inline body", func(t *testing.T) {
		src := "<?php\nfunction run($c){ system(escapeshellarg($c)); }\n$v = $_GET['c'];\nrun($v);\n"
		if ids := analyzeRuleIDs(t, "t.php", lexctx.LangPHP, src); len(ids) != 0 {
			t.Fatalf("sanitized inline body must not fire, got %v", ids)
		}
	})
}

// --- F5: JS per-function scoping (no cross-scope false positive) ---

func TestRecallF5_JSFunctionScoping(t *testing.T) {
	t.Run("negative/module var does not taint unrelated param", func(t *testing.T) {
		// The FP this fix removes: a module-level tainted variable must not taint a
		// same-named PARAMETER of an unrelated function.
		src := "const cmd = req.query;\nfunction unrelated(cmd) {\n    child_process.exec(cmd);\n}\n"
		if ids := analyzeRuleIDs(t, "t.js", lexctx.LangJavaScript, src); len(ids) != 0 {
			t.Fatalf("module var leaked into unrelated param, got %v", ids)
		}
	})
	t.Run("positive/same-function flow still fires", func(t *testing.T) {
		// Scoping must not hide a genuine same-function flow.
		src := "function h(req) {\n    const cmd = req.query;\n    child_process.exec(cmd);\n}\n"
		if ids := analyzeRuleIDs(t, "t.js", lexctx.LangJavaScript, src); !containsStr(ids, "TAINT-002") {
			t.Fatalf("same-function flow missed, got %v", ids)
		}
	})
	t.Run("positive/scoped function with param+source flow fires", func(t *testing.T) {
		// A named function scope with an attribute-source read and sink still fires
		// (F2 within a per-function unit), proving scoping did not hide the flow.
		src := "function handler(req) {\n    const id = req.query.id;\n    child_process.exec(id);\n}\n"
		if ids := analyzeRuleIDs(t, "t.js", lexctx.LangJavaScript, src); !containsStr(ids, "TAINT-002") {
			t.Fatalf("scoped-function flow missed, got %v", ids)
		}
	})
}
