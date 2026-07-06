package lexctx

import "testing"

// TestScanDart exercises the headline Dart lexical roles the same way
// TestScanSwift / TestScanGo do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and taint analyzers rely on
// when gating findings in Dart source.
func TestScanDart(t *testing.T) {
	src := "final apiKey = 's3cr3t';\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"final raw = r'template s3cr3t line';\n" +
		"final multi = '''\nblock s3cr3t body\n''';\n"
	if k := kindOfSubstring(t, LangDart, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `'s3cr3t'`); k != KindString {
		t.Errorf("single-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `template s3cr3t line`); k != KindString {
		t.Errorf("raw string literal body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `block s3cr3t body`); k != KindString {
		t.Errorf("triple-quoted string body should be string, got %v", k)
	}
}

func TestDartLangFromPath(t *testing.T) {
	if got := LangFromPath("lib/src/handler.dart"); got != LangDart {
		t.Errorf("LangFromPath(.dart) = %v, want %v", got, LangDart)
	}
	if got := LangFromPath("UPPER.DART"); got != LangDart {
		t.Errorf("LangFromPath is not case-insensitive for .dart, got %v", got)
	}
}

func TestDartLangString(t *testing.T) {
	if got := LangDart.String(); got != "dart" {
		t.Errorf("LangDart.String() = %q, want %q", got, "dart")
	}
}

// TestDartLineComment: a `//` runs to end of line; the following line is code.
func TestDartLineComment(t *testing.T) {
	src := "var x = 1; // comment SECRET here\nvar y = 2;"
	if k := kindOfSubstring(t, LangDart, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `var y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestDartDocComment: a `///` doc comment behaves like a line comment.
func TestDartDocComment(t *testing.T) {
	src := "/// doc comment SECRET here\nvar y = 2;"
	if k := kindOfSubstring(t, LangDart, src, `doc comment SECRET here`); k != KindComment {
		t.Errorf("doc-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `var y = 2`); k != KindCode {
		t.Errorf("code after a doc comment should be code, got %v", k)
	}
}

// TestDartBlockCommentNested pins the NESTING rule (Dart allows nested block
// comments, unlike Go/C): an inner `/*` opens a nested comment whose `*/` does
// NOT close the outer one — only the matching outer `*/` does, so the trailing
// SECRET stays comment and the CODE after the outer close is code.
func TestDartBlockCommentNested(t *testing.T) {
	src := "/* outer /* inner */ still comment SECRET */ CODE = 1;"
	if k := kindOfSubstring(t, LangDart, src, `inner`); k != KindComment {
		t.Errorf("inner nested comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `still comment SECRET`); k != KindComment {
		t.Errorf("text after the inner close but before the outer close must stay comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `CODE`); k != KindCode {
		t.Errorf("code after the matching outer `*/` should be code, got %v", k)
	}
}

// TestDartBlockCommentSpansLines: `/* ... */` crosses newlines.
func TestDartBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangDart, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestDartDoubleQuoteEscapedQuote: `\"` must not close a double-quoted string.
func TestDartDoubleQuoteEscapedQuote(t *testing.T) {
	src := `var s = "a\"b"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestDartSingleQuoteString: Dart uses `'...'` as freely as `"..."`.
func TestDartSingleQuoteString(t *testing.T) {
	src := `var s = 'hello world'; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `hello world`); k != KindString {
		t.Errorf("single-quoted body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after a single-quoted string should be code, got %v", k)
	}
}

// TestDartSimpleInterpolation: `$var` is an interpolation hole whose identifier
// is emitted as CODE — a tainted value spliced via 'id=$userInput' lives in a
// real expression the taint engine must see. The surrounding literal text stays
// string.
func TestDartSimpleInterpolation(t *testing.T) {
	src := `var s = 'hi $name and bye'; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `name`); k != KindCode {
		t.Errorf("simple `$var` interpolation identifier should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `hi `); k != KindString {
		t.Errorf("literal text before the hole should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, ` and bye`); k != KindString {
		t.Errorf("literal text after the hole should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after an interpolated string should be code, got %v", k)
	}
}

// TestDartBracedInterpolation: `${expr}` is an interpolation hole whose
// CONTENTS are emitted as CODE, and the `}` of the hole must not be mistaken
// for anything — the string still terminates at its real closing quote.
func TestDartBracedInterpolation(t *testing.T) {
	src := `var s = "x ${f(g(y))} z"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `f(g(y))`); k != KindCode {
		t.Errorf("braced interpolation contents should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, ` z"`); k != KindString {
		t.Errorf("tail of the string after a nested-brace hole should stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestDartBracedInterpolationNestedString: a string literal INSIDE `${...}`
// (with its own `}` inside) must not close the hole early.
func TestDartBracedInterpolationNestedString(t *testing.T) {
	src := `var s = "a ${m['k}']} b"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, ` b"`); k != KindString {
		t.Errorf("tail after a hole containing a nested string should stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestDartRawStringNoInterpolation: a raw string `r'...'` processes NO escapes
// and NO interpolation — a `$` and a `\` are literal bytes.
func TestDartRawStringNoInterpolation(t *testing.T) {
	src := `var r = r'a\$name\n'; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `a\$name\n`); k != KindString {
		t.Errorf("raw-string body (escapes/interp are literal) should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after a raw string should be code, got %v", k)
	}
}

// TestDartRawStringDoubleQuote: raw strings work with `"` too: `r"..."`.
func TestDartRawStringDoubleQuote(t *testing.T) {
	src := `var r = r"a\$name"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `a\$name`); k != KindString {
		t.Errorf("double-quoted raw-string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after a double-quoted raw string should be code, got %v", k)
	}
}

// TestDartTripleQuoteString: a triple-single-quote string spans lines; interior
// single `'`, `"` and `//` are literal. The trailing code stays code, and simple
// interpolation still works inside it.
func TestDartTripleQuoteString(t *testing.T) {
	src := "var s = '''\nline1 // not a comment\nline2 'not a close' SECRET\n''';\nvar after = 1;"
	if k := kindOfSubstring(t, LangDart, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a triple-quoted string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `not a close`); k != KindString {
		t.Errorf("a single `'` inside a triple-quoted string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `after`); k != KindCode {
		t.Errorf("code after a triple-quoted string should be code, got %v", k)
	}
}

// TestDartTripleDoubleQuoteString: `"""..."""` is the double-quoted multiline form.
func TestDartTripleDoubleQuoteString(t *testing.T) {
	src := "var s = \"\"\"\nbody 'single' and \"double\" SECRET\n\"\"\";\nvar after = 1;"
	if k := kindOfSubstring(t, LangDart, src, `body 'single'`); k != KindString {
		t.Errorf("triple-double-quoted string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `after`); k != KindCode {
		t.Errorf("code after a triple-double-quoted string should be code, got %v", k)
	}
}

// TestDartRawTripleQuoteString: an `r`-prefixed triple-single-quote string is a
// raw multiline string — no interpolation, spans lines.
func TestDartRawTripleQuoteString(t *testing.T) {
	src := "var s = r'''\nraw $name \\n body SECRET\n''';\nvar after = 1;"
	if k := kindOfSubstring(t, LangDart, src, `raw $name`); k != KindString {
		t.Errorf("raw triple-quoted body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `after`); k != KindCode {
		t.Errorf("code after a raw triple-quoted string should be code, got %v", k)
	}
}

// TestDartDoubleSlashInsideStringIsNotComment: a URL's `//` inside a string
// must not begin a comment.
func TestDartDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `var url = "https://example.com/path"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangDart, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangDart, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestDartDataBlobSuppressed proves the payoff: a long base64/data-URI payload
// inside a Dart raw string is a blob (suppressed), while a short secret in an
// ordinary string is NOT.
func TestDartDataBlobSuppressed(t *testing.T) {
	longBlob := "final icon = r'data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==';"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangDart, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI raw-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`final apiKey = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangDart, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Dart string must NOT be a data blob")
	}
}

// TestDartSuppressNonCodePolicy mirrors the Go/Swift policy tests for Dart: a
// comment match and a data-blob-string match are dropped by SuppressNonCode,
// while a short ordinary-string secret is kept.
func TestDartSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("var x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangDart, comment, k, k+32) {
		t.Error("a token inside a Dart comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`var key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangDart, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Dart string literal must NOT be suppressed")
	}
}

// TestDartRegionsCoverAndAscending guards the region-list contract on a mixed
// fixture: contiguous, gap-free, ascending coverage of the whole input.
func TestDartRegionsCoverAndAscending(t *testing.T) {
	src := "var a = 's';\n/* c /* n */ */\nvar b = r'r';\nvar m = '''\nx $y\n''';\nvar d = \"p ${q} r\";\n"
	regions := Classify(LangDart, []byte(src))
	regionsCover(t, regions, len(src))
}
