package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// getterSource answers most functions without the unseeded pass
// (mayReturnASource). Its answer must be the pass's on every function: the
// repository's taint suites, and NOX_GETTER_CORPUS when set (crewAI).
func TestGetterPrecheckMatchesThePass(t *testing.T) {
	roots := []string{"../../../testdata"}
	if c := os.Getenv("NOX_GETTER_CORPUS"); c != "" {
		roots = append(roots, c)
	}
	e := NewStructuralEngine(nil)
	var funcs, skipped, getters int
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			lang := lexctx.LangFromPath(p)
			if lang == lexctx.LangUnknown {
				return nil
			}
			content, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			units := ExtractUnits(p, lang, content)
			if len(units) == 0 {
				return nil
			}
			summaries := e.computeSummaries(units[0].Language, units)
			for i := range units {
				u := &units[i]
				if u.FuncName == "" {
					continue
				}
				funcs++
				want := e.passGetterSource(u.Language, u, summaries)
				if want != nil {
					getters++
				}
				if !e.mayReturnASource(u.Language, u) {
					skipped++
				}
				if got := e.getterSource(u.Language, u, summaries); !reflect.DeepEqual(got, want) {
					t.Errorf("%s %s: getterSource %+v, the pass %+v", p, u.FuncName, got, want)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Getters whose return names its source directly, beside functions
	// returning a constant, in three languages.
	for path, src := range map[string]string{
		"direct.php": "<?php\nfunction q() {\n  return $_GET['q'];\n}\nfunction c() {\n  return 1;\n}\n",
		"direct.py":  "from flask import request\n\ndef q():\n    return request.args.get('q')\n\ndef c():\n    return None\n",
		"direct.js":  "function q(req) {\n  return req.query.q;\n}\nfunction c() {\n  return 1;\n}\n",
	} {
		units := ExtractUnits(path, lexctx.LangFromPath(path), []byte(src))
		summaries := e.computeSummaries(units[0].Language, units)
		for i := range units {
			u := &units[i]
			if u.FuncName == "" {
				continue
			}
			funcs++
			want := e.passGetterSource(u.Language, u, summaries)
			if want != nil {
				getters++
			}
			if got := e.getterSource(u.Language, u, summaries); !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: getterSource %+v, the pass %+v", path, u.FuncName, got, want)
			}
		}
	}
	t.Logf("%d functions: %d answered without the pass, %d getters", funcs, skipped, getters)
	if skipped == 0 || getters == 0 || skipped == funcs {
		t.Fatalf("the corpus does not exercise both answers: %d functions, %d skipped, %d getters", funcs, skipped, getters)
	}
}

// Extraction records a call's base name as a read (`return input()` reads
// `input`), so no return the suites or crewAI hold names a source with no
// read. mayReturnASource must still keep the function for the pass if one
// does, as the pass would find it a getter.
func TestGetterPrecheckKeepsADirectSourceWithNoRead(t *testing.T) {
	e := NewStructuralEngine(nil)
	u := &taint.Unit{Language: "python", FuncName: "q", Stmts: []taint.Statement{
		{Line: 2, IsReturn: true, Calls: []string{"input"}},
	}}
	if !e.mayReturnASource("python", u) {
		t.Fatal("a return calling input() and reading nothing was answered without the pass")
	}
	u.Stmts[0].Calls = nil
	if e.mayReturnASource("python", u) {
		t.Fatal("a bare return reading nothing was sent to the pass")
	}
}
