package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func jsTreeUnits(t *testing.T, path, src string) []unitDraft {
	t.Helper()
	content := []byte(src)
	lines, ok := jsTreeLines(path, content, lexctx.Classify(lexctx.LangJavaScript, content))
	if !ok {
		t.Fatalf("the parser declined %s", path)
	}
	return extractJavaScript(splitSemicolons(lines))
}

func jsStmtAssigning(us []unitDraft, unit, v string) *stmtDraft {
	for _, u := range us {
		if u.funcName != unit {
			continue
		}
		for i := range u.stmts {
			if u.stmts[i].assigns == v {
				return &u.stmts[i]
			}
		}
	}
	return nil
}

func TestJSTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("a concatenation continued on the next line", func(t *testing.T) {
		us := jsTreeUnits(t, "r.js", "function h(req, db) {\n  const q = \"SELECT * FROM t WHERE id = \" +\n    req.query.id;\n  return db.query(q);\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "req") {
			t.Fatalf("q must read req; got %+v", s)
		}
	})
	t.Run("a call chain continued on the next line", func(t *testing.T) {
		// The receiver and the method are on different lines: only the joined
		// statement calls db.query.
		us := jsTreeUnits(t, "r.js", "function h(req, db) {\n  const q = req.query.q;\n  return db\n    .query(q);\n}\n")
		found := false
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "db.query") && slices.Contains(st.reads, "q") {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("no statement calls db.query with q; got %+v", us)
		}
	})
	t.Run("declarators stay separate bindings", func(t *testing.T) {
		us := jsTreeUnits(t, "r.js", "function h(req) {\n  var a = req.query.a,\n      b = clean(a);\n  return b;\n}\n")
		if s := jsStmtAssigning(us, "h", "a"); s == nil || slices.Contains(s.reads, "clean") {
			t.Fatalf("a's binding must not take b's declarator; got %+v", s)
		}
	})
	t.Run("a callback body stays in its function", func(t *testing.T) {
		us := jsTreeUnits(t, "r.js", "app.get('/u', (req, res) => {\n  const id = req.query.id;\n  res.send(id);\n});\n")
		found := false
		for _, u := range us { // the callback is anonymous: find it by its parameters
			if slices.Equal(u.params, []string{"req", "res"}) && jsStmtAssigning([]unitDraft{u}, u.funcName, "id") != nil {
				found = true
			}
		}
		if !found {
			t.Fatalf("id must be bound inside the callback's unit; got %+v", us)
		}
	})
}

// A TypeScript file parses with the TypeScript grammar: type annotations are
// no error tree, so the file is joined rather than declined.
func TestJSTreeTypeScriptGrammar(t *testing.T) {
	src := "export async function h(req: Request, db: Db): Promise<Row[]> {\n  const q: string = \"SELECT * FROM t WHERE id = \" +\n    req.query.id;\n  return db.query(q);\n}\n"
	content := []byte(src)
	if _, ok := jsTreeLines("route.ts", content, lexctx.Classify(lexctx.LangJavaScript, content)); !ok {
		t.Fatal("a .ts file with type annotations was declined")
	}
	if jsGrammar("a.tsx") != "tsx" || jsGrammar("a.mts") != "typescript" || jsGrammar("a.mjs") != "javascript" {
		t.Error("jsGrammar chose the wrong grammar")
	}
}

// A chain continued after a line ending in a comment keeps its receiver: the
// comment is blanked to spaces in the code view, and those spaces would
// split the chain as surely as the line break.
func TestJSTreeChainAfterATrailingComment(t *testing.T) {
	us := jsTreeUnits(t, "r.js", "function h(req, db) {\n  const q = req.query.q;\n  return db // the pool\n    .query(q);\n}\n")
	for _, u := range us {
		for _, st := range u.stmts {
			if slices.Contains(st.calls, "db.query") {
				return
			}
		}
	}
	t.Fatalf("no statement calls db.query; got %+v", us)
}
