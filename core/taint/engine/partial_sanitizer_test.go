package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A canonicalizer is not a defence on its own: filepath.Clean("../../etc/passwd")
// is still "../../etc/passwd", and realpath resolves a traversal rather than
// refusing it. Each case below is the same function three ways — the canonical
// safe form (canonicalize, then refuse anything outside the base), the same code
// with the check removed, and the check applied to a different variable. Only
// the first is safe.
type partialCase struct {
	name, file string
	lang       lexctx.Lang
	// guarded is the safe form. {CHECK} marks the check's line; unguarded
	// deletes it and elsewhere replaces its subject with an unrelated variable.
	guarded, check, elsewhere string
}

var partialCases = []partialCase{
	{
		name: "go filepath.Clean", file: "t.go", lang: lexctx.LangGo,
		guarded: `package f
func serve(w W, r *Req) {
	p := filepath.Clean(r.URL.Query().Get("file"))
	{CHECK}
	_, _ = os.ReadFile(p)
}`,
		check:     `if !strings.HasPrefix(p, base) { return }`,
		elsewhere: `if !strings.HasPrefix(other, base) { return }`,
	},
	{
		name: "go filepath.Clean on a tainted variable", file: "t.go", lang: lexctx.LangGo,
		guarded: `package f
func serve(w W, r *Req) {
	name := r.URL.Query().Get("file")
	p := filepath.Join(base, filepath.Clean("/"+name))
	{CHECK}
	_, _ = os.ReadFile(p)
}`,
		check:     `if rel, err := filepath.Rel(base, p); err != nil || strings.HasPrefix(rel, "..") { return }`,
		elsewhere: `if rel, err := filepath.Rel(base, other); err != nil || strings.HasPrefix(rel, "..") { return }`,
	},
	{
		name: "python os.path.realpath", file: "t.py", lang: lexctx.LangPython,
		guarded: `def serve():
    p = os.path.realpath(request.args.get("f"))
    {CHECK}
    return open(p).read()
`,
		check:     `if not p.startswith(BASE): abort(403)`,
		elsewhere: `if not other.startswith(BASE): abort(403)`,
	},
	{
		name: "javascript path.resolve", file: "t.js", lang: lexctx.LangJavaScript,
		guarded: `function serve(req, res) {
  const p = path.resolve(BASE, req.query.f);
  {CHECK}
  fs.readFileSync(p);
}`,
		check:     `if (!p.startsWith(BASE)) { return res.end(); }`,
		elsewhere: `if (!other.startsWith(BASE)) { return res.end(); }`,
	},
	{
		name: "php realpath", file: "t.php", lang: lexctx.LangPHP,
		guarded: `<?php
function serve() {
  $p = realpath($_GET['f']);
  {CHECK}
  readfile($p);
}`,
		check:     `if (!str_starts_with($p, BASE)) { exit; }`,
		elsewhere: `if (!str_starts_with($other, BASE)) { exit; }`,
	},
	{
		name: "java Path.normalize", file: "T.java", lang: lexctx.LangJava,
		guarded: `class T {
  void serve(HttpServletRequest request) {
    Path p = Paths.get(request.getParameter("f")).normalize();
    {CHECK}
    Files.readAllBytes(p);
  }
}`,
		check:     `if (!p.startsWith(BASE)) { return; }`,
		elsewhere: `if (!other.startsWith(BASE)) { return; }`,
	},
	{
		name: "kotlin Path.normalize", file: "t.kt", lang: lexctx.LangKotlin,
		guarded: `fun serve(request: HttpServletRequest) {
    val p = Paths.get(request.getParameter("f")).normalize()
    {CHECK}
    Files.readAllBytes(p)
}`,
		check:     `if (!p.startsWith(BASE)) { return }`,
		elsewhere: `if (!other.startsWith(BASE)) { return }`,
	},
	{
		name: "c realpath", file: "t.c", lang: lexctx.LangCPP,
		guarded: `void serve(void) {
  char *p = realpath(getenv("F"), NULL);
  {CHECK}
  fopen(p, "r");
}`,
		check:     `if (strncmp(p, BASE, strlen(BASE)) != 0) { return; }`,
		elsewhere: `if (strncmp(other, BASE, strlen(BASE)) != 0) { return; }`,
	},
}

func analyzePartial(t *testing.T, c partialCase, check string) []string {
	t.Helper()
	src := strings.Replace(c.guarded, "{CHECK}", check, 1)
	return ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(c.file, c.lang, []byte(src))))
}

func TestCanonicalizerPairedWithACheckIsSafe(t *testing.T) {
	for _, c := range partialCases {
		t.Run(c.name, func(t *testing.T) {
			if ids := analyzePartial(t, c, c.check); len(ids) != 0 {
				t.Errorf("canonicalize-then-check fired %v, want nothing", ids)
			}
		})
	}
}

func TestCanonicalizerAloneDoesNotContainTraversal(t *testing.T) {
	for _, c := range partialCases {
		t.Run(c.name, func(t *testing.T) {
			if ids := analyzePartial(t, c, ""); !contains(ids, "TAINT-004") {
				t.Errorf("canonicalized path with no check reached the file sink unreported: got %v, want TAINT-004", ids)
			}
		})
	}
}

func TestACheckOnAnotherValueDoesNotCount(t *testing.T) {
	for _, c := range partialCases {
		t.Run(c.name, func(t *testing.T) {
			if ids := analyzePartial(t, c, c.elsewhere); !contains(ids, "TAINT-004") {
				t.Errorf("a check on an unrelated variable cleared the canonicalized path: got %v, want TAINT-004", ids)
			}
		})
	}
}

// A check that runs BEFORE canonicalization proves nothing about the result:
// HasPrefix("/srv/../etc/passwd", "/srv/") is true, and Clean then yields
// "/etc/passwd".
func TestACheckBeforeCanonicalizationDoesNotCount(t *testing.T) {
	src := `package f
func serve(w W, r *Req) {
	name := r.URL.Query().Get("file")
	if !strings.HasPrefix(name, "/srv/") { return }
	p := filepath.Clean(name)
	_, _ = os.ReadFile(p)
}`
	ids := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("t.go", lexctx.LangGo, []byte(src))))
	if !contains(ids, "TAINT-004") {
		t.Errorf("a prefix check on the raw input cleared the cleaned path: got %v, want TAINT-004", ids)
	}
}

// Canonicalizing inside the sink call leaves no variable to check.
func TestCanonicalizerInsideTheSinkCallIsNotADefence(t *testing.T) {
	src := `package f
func serve(w W, r *Req) {
	name := r.URL.Query().Get("file")
	_, _ = os.ReadFile(filepath.Clean(name))
}`
	ids := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("t.go", lexctx.LangGo, []byte(src))))
	if !contains(ids, "TAINT-004") {
		t.Errorf("ReadFile(Clean(input)) went unreported: got %v, want TAINT-004", ids)
	}
}

// Stripping the directory components is a defence on its own; it must keep
// clearing with no check.
func TestBasenameStillClearsWithoutACheck(t *testing.T) {
	src := `package f
func serve(w W, r *Req) {
	name := filepath.Base(r.URL.Query().Get("file"))
	_, _ = os.ReadFile(filepath.Join("/srv", name))
}`
	if ids := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("t.go", lexctx.LangGo, []byte(src)))); len(ids) != 0 {
		t.Errorf("filepath.Base fired %v, want nothing", ids)
	}
}

// Parsing a URL does not restrict where it points: url.parse, urlparse and
// URI.parse return the attacker's host intact. A host allowlist is the defence,
// and it cannot be told apart from a scheme check (`['http:',
// 'https:'].includes(u.protocol)`) by the calls it makes, so parsing clears
// nothing and an allowlisted fetch is left to a waiver.
func TestURLParsingIsNotAnSSRFDefence(t *testing.T) {
	for _, c := range []struct {
		name, file string
		lang       lexctx.Lang
		src        string
	}{
		{"javascript url.parse", "t.js", lexctx.LangJavaScript, "function h(req, res) {\n  const u = url.parse(req.query.u);\n  http.get(u);\n}"},
		{"javascript new URL", "t.js", lexctx.LangJavaScript, "function h(req, res) {\n  fetch(new URL(req.query.u));\n}"},
		{"python urllib.parse.urlparse", "t.py", lexctx.LangPython, "def h():\n    u = urllib.parse.urlparse(request.args.get('u'))\n    requests.get(u.geturl())\n"},
		{"ruby URI.parse", "t.rb", lexctx.LangRuby, "def h\n  u = URI.parse(params[:u])\n  Net::HTTP.get(u)\nend\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ids := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(c.file, c.lang, []byte(c.src))))
			if !contains(ids, "TAINT-006") {
				t.Errorf("a parsed, unchecked URL reached the request sink unreported: got %v, want TAINT-006", ids)
			}
		})
	}
}
