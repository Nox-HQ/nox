package lexctx

import "testing"

// TestScanGroovy exercises the headline Groovy lexical roles the same way
// TestScanKotlin / TestScanGo do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and taint analyzers rely on when
// gating findings in Groovy / Gradle / Jenkinsfile source.
func TestScanGroovy(t *testing.T) {
	src := "def apiKey = \"s3cr3t\"\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"def gstr = \"hello ${user} s3cr3t\"\n" +
		"def plain = 'plain s3cr3t here'\n" +
		"def raw = \"\"\"template s3cr3t line\"\"\"\n" +
		"def rawp = '''plain s3cr3t block'''\n"
	if k := kindOfSubstring(t, LangGroovy, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted GString literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	// A GString's literal parts are string, but its `${...}` interpolation hole is
	// emitted as CODE (like Swift's `\(…)`) so a tainted value spliced through it is
	// visible to the taint engine.
	if k := kindOfSubstring(t, LangGroovy, src, `hello `); k != KindString {
		t.Errorf("GString literal prefix should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `user`); k != KindCode {
		t.Errorf("GString ${...} interpolation expression should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `plain s3cr3t here`); k != KindString {
		t.Errorf("single-quoted plain string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `template s3cr3t line`); k != KindString {
		t.Errorf("triple-double-quoted string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `plain s3cr3t block`); k != KindString {
		t.Errorf("triple-single-quoted string should be string, got %v", k)
	}
}

// TestGroovyLangFromPath: `.groovy`, `.gradle`, and the extension-less
// `Jenkinsfile` (by base name, like Ruby's Gemfile) all map to LangGroovy;
// detection is case-insensitive on the extension.
func TestGroovyLangFromPath(t *testing.T) {
	cases := map[string]Lang{
		"src/main/Report.groovy":   LangGroovy,
		"build.gradle":             LangGroovy,
		"deep/nested/build.gradle": LangGroovy,
		"ci/Jenkinsfile":           LangGroovy,
		"Jenkinsfile":              LangGroovy,
		"UPPER.GROOVY":             LangGroovy,
		"build.gradle.kts":         LangKotlin, // .kts wins — Kotlin Gradle DSL
		"notgroovy.txt":            LangUnknown,
	}
	for path, want := range cases {
		if got := LangFromPath(path); got != want {
			t.Errorf("LangFromPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestGroovyLangString(t *testing.T) {
	if got := LangGroovy.String(); got != "groovy" {
		t.Errorf("LangGroovy.String() = %q, want %q", got, "groovy")
	}
}

// TestGroovyLineComment: a `//` runs to end of line; the following line is code.
func TestGroovyLineComment(t *testing.T) {
	src := "def x = 1 // comment SECRET here\ndef y = 2"
	if k := kindOfSubstring(t, LangGroovy, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `def y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestGroovyBlockCommentNoNest pins that Groovy block comments do NOT nest
// (unlike Kotlin/Scala): the FIRST `*/` closes, so the trailing text is code.
func TestGroovyBlockCommentNoNest(t *testing.T) {
	src := "/* outer /* inner */ SECRET_VAR = 1"
	if k := kindOfSubstring(t, LangGroovy, src, `inner`); k != KindComment {
		t.Errorf("bytes before the first `*/` should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `SECRET_VAR`); k != KindCode {
		t.Errorf("bytes after the first `*/` should be code (no nesting), got %v", k)
	}
}

// TestGroovyTripleSpansLines: `"""..."""` crosses newlines and a single interior
// `"` does not close it.
func TestGroovyTripleSpansLines(t *testing.T) {
	src := "def q = \"\"\"\nSELECT * FROM t WHERE name = \"x\" AND id SECRET\n\"\"\"\ndef after = 1"
	if k := kindOfSubstring(t, LangGroovy, src, `id SECRET`); k != KindString {
		t.Errorf("multi-line triple-quoted body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `def after = 1`); k != KindCode {
		t.Errorf("code after a triple-quoted string should be code, got %v", k)
	}
}

// TestGroovySlashyString: a slashy string `/.../` opening where an expression may
// start (here after `=`) is a string; a `/` used as division stays code.
func TestGroovySlashyString(t *testing.T) {
	src := "def re = /^SECRET-\\d+$/\ndef q = a / b\n"
	if k := kindOfSubstring(t, LangGroovy, src, `^SECRET-`); k != KindString {
		t.Errorf("slashy string body should be string, got %v", k)
	}
	// The division `a / b` must remain code — a `/` after an identifier is not a
	// slashy string.
	if k := kindOfSubstring(t, LangGroovy, src, `a / b`); k != KindCode {
		t.Errorf("division operator should stay code, got %v", k)
	}
}

// TestGroovyDollarSlashy: a `$/.../$` dollar-slashy string spans lines and holds
// a `/` without closing; the code after `/$` is code again.
func TestGroovyDollarSlashy(t *testing.T) {
	src := "def p = $/C:\\path\\to SECRET/some/thing/$\ndef after = 2"
	if k := kindOfSubstring(t, LangGroovy, src, `to SECRET`); k != KindString {
		t.Errorf("dollar-slashy body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `def after = 2`); k != KindCode {
		t.Errorf("code after `/$` should be code, got %v", k)
	}
}

// TestGroovyBareVarInterpolation: a bare `$var` GString interpolation emits the
// identifier as CODE (so the taint engine reads it) while the surrounding literal
// stays string; a plain single-quoted string does NOT interpolate.
func TestGroovyBareVarInterpolation(t *testing.T) {
	src := "def a = \"run $cmd now\"\ndef b = 'literal $cmd here'\n"
	if k := kindOfSubstring(t, LangGroovy, src, `run `); k != KindString {
		t.Errorf("GString literal prefix should be string, got %v", k)
	}
	// The `$cmd` identifier (after the `$`) is code — first occurrence is on line 1.
	if k := kindOfSubstring(t, LangGroovy, src, `cmd`); k != KindCode {
		t.Errorf("bare $var interpolation identifier should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `literal $cmd here`); k != KindString {
		t.Errorf("plain single-quoted string must NOT interpolate (all string), got %v", k)
	}
}

// TestGroovySlashyInterpolation: a slashy string interpolates `${...}` as code.
func TestGroovySlashyInterpolation(t *testing.T) {
	src := "def re = /prefix-${host}-suffix/\n"
	if k := kindOfSubstring(t, LangGroovy, src, `prefix-`); k != KindString {
		t.Errorf("slashy literal part should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `host`); k != KindCode {
		t.Errorf("slashy ${...} interpolation expression should be code, got %v", k)
	}
}

// TestGroovyDataBlobTriple: a base64/data-URI blob inside a triple-quoted string
// is a string (and InDataBlob suppresses secret FPs there), while a genuine short
// hardcoded secret in an ordinary string is kept.
func TestGroovyDataBlobTriple(t *testing.T) {
	blob := "def img = \"\"\"data:image/png;base64," +
		"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVV\"\"\"\n"
	regions := Classify(LangGroovy, []byte(blob))
	idx := indexOf(blob, "data:image")
	if InCode(regions, idx, idx+len("data:image")) {
		t.Errorf("data-URI inside a triple-quoted string must not be code")
	}
	if !InDataBlob(LangGroovy, []byte(blob), idx, idx+len("data:image")) {
		t.Errorf("data-URI inside a triple-quoted string should be a data blob (secret FP suppressed)")
	}
}

// TestGroovyShebang: a leading `#!` shebang on line 1 is a comment.
func TestGroovyShebang(t *testing.T) {
	src := "#!/usr/bin/env groovy SECRET\ndef x = 1"
	if k := kindOfSubstring(t, LangGroovy, src, `env groovy SECRET`); k != KindComment {
		t.Errorf("shebang line should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGroovy, src, `def x = 1`); k != KindCode {
		t.Errorf("code after shebang should be code, got %v", k)
	}
}
