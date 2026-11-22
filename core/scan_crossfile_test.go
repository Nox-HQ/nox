package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func writeCrossTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func taintFindings(t *testing.T, dir string) []findings.Finding {
	t.Helper()
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	var out []findings.Finding
	for _, f := range res.Findings.Findings() {
		if strings.HasPrefix(f.RuleID, "TAINT-") {
			out = append(out, f)
		}
	}
	return out
}

// ADR 0007: a source in one file reaching a sink in another, through a call
// the call graph binds by the caller's import, is reported at the sink, with
// the calls as evidence.
func TestScan_CrossFileTaint(t *testing.T) {
	helpers := "import os\n\n\ndef run_cmd(c):\n    os.system(\"ls \" + c)\n"
	views := "from flask import request\nfrom app.helpers import run_cmd\n\n\ndef handler():\n    name = request.args.get(\"name\")\n    run_cmd(name)\n"

	t.Run("python, a module import", func(t *testing.T) {
		got := taintFindings(t, writeCrossTree(t, map[string]string{"app/helpers.py": helpers, "app/views.py": views}))
		if len(got) != 1 {
			t.Fatalf("want one finding, got %+v", got)
		}
		f := got[0]
		if f.RuleID != "TAINT-002" || f.Location.FilePath != "app/helpers.py" || f.Location.StartLine != 5 {
			t.Fatalf("want TAINT-002 at app/helpers.py:5, got %s %s:%d", f.RuleID, f.Location.FilePath, f.Location.StartLine)
		}
		if f.Metadata["cross_file"] != "true" || f.Metadata["source_file"] != "app/views.py" || f.Metadata["source_line"] != "6" {
			t.Errorf("metadata %v", f.Metadata)
		}
		if p := f.Metadata["flow_path"]; p != "handler (app/views.py:7) -> run_cmd (app/helpers.py:5)" {
			t.Errorf("flow_path = %q", p)
		}
	})

	t.Run("javascript, a relative require", func(t *testing.T) {
		got := taintFindings(t, writeCrossTree(t, map[string]string{
			"src/db.js":     "const { exec } = require('child_process');\n\nfunction runIt(cmd) {\n  exec('ls ' + cmd);\n}\n\nmodule.exports = { runIt };\n",
			"src/routes.js": "const db = require('./db');\n\napp.get('/x', (req, res) => {\n  db.runIt(req.query.name);\n});\n",
		}))
		if len(got) != 1 || got[0].Location.FilePath != "src/db.js" || got[0].Location.StartLine != 4 {
			t.Fatalf("want one finding at src/db.js:4, got %+v", got)
		}
	})

	t.Run("a getter in another file names its file as the source", func(t *testing.T) {
		got := taintFindings(t, writeCrossTree(t, map[string]string{
			"app/inputs.py": "from flask import request\n\n\ndef user_name():\n    return request.args.get(\"name\")\n",
			"app/views.py":  "import os\nfrom app.inputs import user_name\n\n\ndef handler():\n    n = user_name()\n    os.system(\"ls \" + n)\n",
		}))
		if len(got) != 1 || got[0].Location.FilePath != "app/views.py" || got[0].Location.StartLine != 7 {
			t.Fatalf("want one finding at app/views.py:7, got %+v", got)
		}
		// The source line is the getter's, so the file must be too.
		if m := got[0].Metadata; m["source_file"] != "app/inputs.py" || m["source_line"] != "5" {
			t.Errorf("source %s:%s, want app/inputs.py:5", m["source_file"], m["source_line"])
		}
	})

	t.Run("a caller in the sink's file and one in another: one finding, both paths", func(t *testing.T) {
		local := helpers + "\n\ndef local_handler():\n    run_cmd(request.args.get(\"q\"))\n"
		got := taintFindings(t, writeCrossTree(t, map[string]string{
			"app/helpers.py": "from flask import request\n" + local,
			"app/views.py":   views,
		}))
		if len(got) != 1 || got[0].Location.FilePath != "app/helpers.py" || got[0].Location.StartLine != 6 {
			t.Fatalf("want one finding at app/helpers.py:6, got %+v", got)
		}
		m := got[0].Metadata
		want := "local_handler (app/helpers.py:10) -> run_cmd (app/helpers.py:6); handler (app/views.py:7) -> run_cmd (app/helpers.py:6)"
		if m["flow_paths"] != want || m["flow_path_count"] != "2" {
			t.Errorf("flow_paths = %q (count %q), want %q", m["flow_paths"], m["flow_path_count"], want)
		}
	})

	t.Run("a helper that sanitizes is no finding", func(t *testing.T) {
		safe := strings.Replace(helpers, `os.system("ls " + c)`, `os.system("ls " + shlex.quote(c))`, 1)
		if got := taintFindings(t, writeCrossTree(t, map[string]string{"app/helpers.py": "import shlex\n" + safe, "app/views.py": views})); len(got) != 0 {
			t.Fatalf("want none, got %+v", got)
		}
	})

	t.Run("two candidates bind to neither", func(t *testing.T) {
		// A bare call with no import: the graph binds it only to the one
		// function of that name among the project's files.
		bare := "from flask import request\n\n\ndef handler():\n    run_cmd(request.args.get(\"name\"))\n"
		one := taintFindings(t, writeCrossTree(t, map[string]string{"a/helpers.py": helpers, "views.py": bare}))
		two := taintFindings(t, writeCrossTree(t, map[string]string{"a/helpers.py": helpers, "b/helpers.py": helpers, "views.py": bare}))
		if len(one) != 1 || len(two) != 0 {
			t.Fatalf("one candidate: %d findings (want 1); two: %d (want 0)", len(one), len(two))
		}
	})

	t.Run("a source supersedes the parameter finding at the sink", func(t *testing.T) {
		dao := "def find_user(db, uid):\n    q = \"SELECT * FROM users WHERE id = '%s'\" % uid\n    return db.execute(q)\n"
		handler := "from flask import request\nfrom app.dao import find_user\n\n\ndef show(db):\n    return find_user(db, request.args.get(\"id\"))\n"
		only := taintFindings(t, writeCrossTree(t, map[string]string{"app/dao.py": dao}))
		if len(only) != 1 || only[0].Confidence != findings.ConfidenceLow {
			t.Fatalf("alone, the DAO is one low-confidence parameter finding; got %+v", only)
		}
		got := taintFindings(t, writeCrossTree(t, map[string]string{"app/dao.py": dao, "app/views.py": handler}))
		if len(got) != 1 || got[0].Metadata["cross_file"] != "true" || got[0].Location.StartLine != only[0].Location.StartLine {
			t.Fatalf("want the cross-file flow alone at line %d, got %+v", only[0].Location.StartLine, got)
		}
	})
}
