package taintflow

import "testing"

// TestAnalyzerGroovyCmdInjectionGString exercises the idiomatic Groovy
// command-injection shape end-to-end: an untrusted request parameter spliced into
// a GString and run via String.execute(). lexctx emits the ${cmd} hole as code so
// the taint engine sees the flow to the .execute sink.
func TestAnalyzerGroovyCmdInjectionGString(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Runner.groovy", `class Runner {
    def go(request) {
        def name = request.getParameter("report")
        "generate-report --name ${name}".execute()
    }
}
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-002" {
		t.Fatalf("want [TAINT-002], got %v", ids)
	}
}

// TestAnalyzerGroovyJenkinsShInterpolation: a Jenkins pipeline `sh` step with a
// tainted GString is command injection.
func TestAnalyzerGroovyJenkinsSh(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Deploy.groovy", `class Deploy {
    def run(request) {
        def branch = request.getParameter("branch")
        sh("git checkout ${branch}")
    }
}
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-002" {
		t.Fatalf("want [TAINT-002], got %v", ids)
	}
}

// TestAnalyzerGroovySQLi: a tainted value concatenated into a Sql.rows query.
func TestAnalyzerGroovySQLi(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Store.groovy", `class Store {
    def lookup(request, sql) {
        def id = request.getParameter("id")
        def q = "SELECT * FROM users WHERE id = '" + id + "'"
        return sql.rows(q)
    }
}
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-001" {
		t.Fatalf("want [TAINT-001], got %v", ids)
	}
}

// TestAnalyzerGroovySQLiParameterizedSafe: a placeholder query passing the tainted
// value as a bind parameter (2nd positional list) must NOT fire.
func TestAnalyzerGroovySQLiParameterizedSafe(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "SafeStore.groovy", `class SafeStore {
    def lookup(request, sql) {
        def id = request.getParameter("id")
        return sql.rows("SELECT * FROM users WHERE id = ?", [id])
    }
}
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (parameterized Sql), got %v", ids)
	}
}

// TestAnalyzerGroovyCodeInjection: a tainted script string handed to Eval.me.
func TestAnalyzerGroovyCodeInjection(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Calc.groovy", `class Calc {
    def eval(request) {
        def expr = request.getParameter("expr")
        return Eval.me(expr)
    }
}
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-005" {
		t.Fatalf("want [TAINT-005], got %v", ids)
	}
}

// TestAnalyzerGroovyPathTraversal: a tainted path opened via new File(path).text.
func TestAnalyzerGroovyPathTraversal(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Reader.groovy", `class Reader {
    def read(request) {
        def p = request.getParameter("path")
        def f = new File(p)
        return f.getText()
    }
}
`)
	ids := scan(t, art)
	if len(ids) == 0 {
		t.Fatalf("want a path-traversal finding, got none")
	}
	found := false
	for _, id := range ids {
		if id == "TAINT-004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want TAINT-004 among %v", ids)
	}
}

// TestAnalyzerGroovySanitizedNumeric: numeric coercion (toInteger) defuses the
// injection, so no finding.
func TestAnalyzerGroovySanitizedNumeric(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Safe.groovy", `class Safe {
    def go(request, sql) {
        def raw = request.getParameter("id")
        def id = raw.toInteger()
        def q = "SELECT * FROM users WHERE id = " + id
        return sql.rows(q)
    }
}
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (numeric coercion), got %v", ids)
	}
}

// TestAnalyzerGroovyNoSourceNoFinding: a constant command with no untrusted input
// must not fire.
func TestAnalyzerGroovyNoSourceNoFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "Const.groovy", `class Const {
    def go() {
        "ls -la".execute()
    }
}
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (no source), got %v", ids)
	}
}
