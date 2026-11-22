package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func treeUnits(t *testing.T, src string) []unitDraft {
	t.Helper()
	content := []byte(src)
	lines, ok := pyTreeLines(content, lexctx.Classify(lexctx.LangPython, content))
	if !ok {
		t.Fatalf("the parser declined %q", src)
	}
	return extractPython(lines)
}

func lineUnits(src string) []unitDraft {
	content := []byte(src)
	return extractPython(logicalLines(content, lexctx.Classify(lexctx.LangPython, content), false))
}

func unitNamed(us []unitDraft, name string) *unitDraft {
	for i := range us {
		if us[i].funcName == name {
			return &us[i]
		}
	}
	return nil
}

// The boundaries the grammar knows and the line segmenter guessed.
func TestPythonTreeSegmentation(t *testing.T) {
	t.Run("semicolons separate statements", func(t *testing.T) {
		u := unitNamed(treeUnits(t, "def h(request):\n    a = request.args.get('a'); os.system(a)\n"), "h")
		if u == nil || len(u.stmts) != 2 || u.stmts[0].assigns != "a" || !slices.Contains(u.stmts[1].calls, "os.system") {
			t.Fatalf("want two statements, a = … then os.system(a); got %+v", u)
		}
	})
	t.Run("a one-line if body is inside the if", func(t *testing.T) {
		u := unitNamed(treeUnits(t, "def h(request, ok):\n    if ok: a = request.args.get('a')\n    return a\n"), "h")
		var body *stmtDraft
		for i := range u.stmts {
			if u.stmts[i].assigns == "a" {
				body = &u.stmts[i]
			}
		}
		if body == nil || !body.conditional {
			t.Fatalf("the body of `if ok:` on its line must be a conditional statement; got %+v", u.stmts)
		}
		// The line segmenter reads the same line as one unconditional statement.
		lu := unitNamed(lineUnits("def h(request, ok):\n    if ok: a = request.args.get('a')\n    return a\n"), "h")
		for _, s := range lu.stmts {
			if s.conditional {
				t.Fatal("the line segmenter was expected to miss this; the test no longer shows the difference")
			}
		}
	})
	t.Run("a triple-quoted string and its format call are one statement", func(t *testing.T) {
		src := "def h(request):\n    name = request.args.get('n')\n    template = '''\n    <p>%s</p>\n    ''' % (name)\n    return render_template_string(template)\n"
		u := unitNamed(treeUnits(t, src), "h")
		found := false
		for _, s := range u.stmts {
			if s.assigns == "template" && slices.Contains(s.reads, "name") {
				found = true
			}
		}
		if !found {
			t.Fatalf("template must be bound from name; got %+v", u.stmts)
		}
	})
	t.Run("a trailing comment is not part of the statement", func(t *testing.T) {
		src := "def h(c, username, text):\n    rows = c.execute(\"INSERT INTO p VALUES (?, ?)\", (username, text)) # WHERE u = \", (username,)\n"
		u := unitNamed(treeUnits(t, src), "h")
		for _, s := range u.stmts {
			for _, v := range s.sqlVars {
				if v == "username" || v == "text" {
					t.Fatalf("%s read as concatenated into SQL from a comment; sqlVars %v", v, s.sqlVars)
				}
			}
		}
	})
	t.Run("a decorated def keeps its parameters and decorator", func(t *testing.T) {
		u := unitNamed(treeUnits(t, "@app.route('/u/<uid>')\ndef show(uid, fmt='json'):\n    return uid\n"), "show")
		if u == nil || !slices.Equal(u.params, []string{"uid", "fmt"}) || u.headerLine != 2 {
			t.Fatalf("got %+v", u)
		}
	})
	t.Run("nested statements keep their function", func(t *testing.T) {
		src := "def outer(request):\n    q = f'''\n    SELECT {request.args.get('id')}\n    '''\n    cursor.execute(q)\n\ndef other():\n    pass\n"
		u := unitNamed(treeUnits(t, src), "outer")
		if u == nil || len(u.stmts) != 2 || !slices.Contains(u.stmts[1].calls, "cursor.execute") {
			t.Fatalf("the multi-line f-string and the execute belong to outer; got %+v", u)
		}
	})
}

// A file the parser declines segments as before.
func TestPythonTreeFallsBackOnAnErrorTree(t *testing.T) {
	content := []byte("def h(:\n    os.system(x)\n")
	if _, ok := pyTreeLines(content, lexctx.Classify(lexctx.LangPython, content)); ok {
		t.Fatal("an error tree was used; it must fall back to the line segmenter")
	}
	t.Setenv("NOX_TAINT_TREESITTER", "python")
	got := extractUnits(lexctx.LangPython, content)
	want := lineUnits(string(content))
	if len(got) != len(want) {
		t.Fatalf("fallback units %d, line segmenter %d", len(got), len(want))
	}
}

func TestTreeFrontEndSwitch(t *testing.T) {
	if !treeFrontEnd("python") || !treeFrontEnd("javascript") {
		t.Error("python and javascript are not on by default")
	}
	t.Setenv("NOX_TAINT_TREESITTER", "none")
	if treeFrontEnd("python") {
		t.Error("NOX_TAINT_TREESITTER=none left python on")
	}
	t.Setenv("NOX_TAINT_TREESITTER", "javascript,python")
	if !treeFrontEnd("python") || !treeFrontEnd("javascript") || treeFrontEnd("java") {
		t.Error("NOX_TAINT_TREESITTER list not honoured")
	}
}
