package lexctx

import "testing"

// TestScanScala exercises the headline Scala lexical roles the same way
// TestScanGo / TestScanCSharp do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and AI analyzers (and the Scala
// taint extractor) rely on when reasoning about Scala source.
func TestScanScala(t *testing.T) {
	src := "val apiKey = \"s3cr3t\"\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"val raw = \"\"\"template s3cr3t line\"\"\"\n" +
		"val greet = s\"hello s3cr3t\"\n" +
		"val c = 's'\n"
	if k := kindOfSubstring(t, LangScala, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `"s3cr3t"`); k != KindString {
		t.Errorf("interpreted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `template s3cr3t line`); k != KindString {
		t.Errorf("triple-quoted string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `hello s3cr3t`); k != KindString {
		t.Errorf("s-interpolator literal body should be string, got %v", k)
	}
}

func TestScalaLangFromPath(t *testing.T) {
	if got := LangFromPath("src/main/scala/App.scala"); got != LangScala {
		t.Errorf("LangFromPath(.scala) = %v, want %v", got, LangScala)
	}
	if got := LangFromPath("build.sc"); got != LangScala {
		t.Errorf("LangFromPath(.sc) = %v, want %v", got, LangScala)
	}
	if got := LangFromPath("APP.SCALA"); got != LangScala {
		t.Errorf("LangFromPath is not case-insensitive for .scala, got %v", got)
	}
}

func TestScalaLangString(t *testing.T) {
	if got := LangScala.String(); got != "scala" {
		t.Errorf("LangScala.String() = %q, want %q", got, "scala")
	}
}

// TestScalaLineComment: a `//` runs to end of line; the following line is code.
func TestScalaLineComment(t *testing.T) {
	src := "val x = 1 // comment SECRET here\nval y = 2"
	if k := kindOfSubstring(t, LangScala, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `val y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestScalaBlockCommentNested pins the NESTING rule: an inner `/*` opens a nested
// comment, so the FIRST `*/` does NOT close the outer one — the bytes after it
// (up to the matching close) are still comment, and only after the balancing
// `*/` is code resumed. This is the crucial difference from Go/Java/C#.
func TestScalaBlockCommentNested(t *testing.T) {
	src := "before\n/* outer /* inner SECRET */ still comment */\nafter := 1"
	if k := kindOfSubstring(t, LangScala, src, `inner SECRET`); k != KindComment {
		t.Errorf("nested-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `still comment`); k != KindComment {
		t.Errorf("bytes after the FIRST `*/` must stay comment (nesting), got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `after`); k != KindCode {
		t.Errorf("code after the balancing `*/` should be code, got %v", k)
	}
}

// TestScalaInterpretedEscapedQuote: `\"` must not close the ordinary string, so
// the trailing code stays code.
func TestScalaInterpretedEscapedQuote(t *testing.T) {
	src := `val s = "a\"b" ; val SECRET = 1`
	if k := kindOfSubstring(t, LangScala, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestScalaInterpretedStringEndsAtNewline: an unterminated ordinary string is
// closed by the newline so the next line's code is not swallowed.
func TestScalaInterpretedStringEndsAtNewline(t *testing.T) {
	src := "val s = \"unterminated\nval SECRET = 1"
	if k := kindOfSubstring(t, LangScala, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestScalaTripleStringSpansLines: `"""..."""` processes NO escapes, spans
// newlines, and interior `//`, `"`, and `\` are literal. A base64/data blob is
// often a triple string. The trailing code stays code.
func TestScalaTripleStringSpansLines(t *testing.T) {
	src := "val blob = \"\"\"line1 // not a comment\nC:\\not\\escaped and \"quoted\" SECRET\"\"\"\nval after = 1"
	if k := kindOfSubstring(t, LangScala, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a triple string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `C:\not\escaped`); k != KindString {
		t.Errorf("`\\` inside a triple string must stay string (no escapes), got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `quoted`); k != KindString {
		t.Errorf("a single interior `\"` inside a triple string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `after`); k != KindCode {
		t.Errorf("code after a multi-line triple string should be code, got %v", k)
	}
}

// TestScalaInterpolatorField: an `s"..."` interpolator classifies its literal
// runs as string and its `$id` / `${expr}` fields as code, so a tainted value
// spliced into the string is seen as real code by the taint engine.
func TestScalaInterpolatorField(t *testing.T) {
	src := "val q = s\"id=$userId and name=${escape(nm)}\""
	if k := kindOfSubstring(t, LangScala, src, `id=`); k != KindString {
		t.Errorf("interpolator literal run should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `userId`); k != KindCode {
		t.Errorf("`$userId` interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `escape(nm)`); k != KindCode {
		t.Errorf("`${escape(nm)}` interpolation field should be code, got %v", k)
	}
}

// TestScalaTripleInterpolator: an `s"""..."""` interpolator spans lines, its
// `${...}` field is code, and the trailing code stays code.
func TestScalaTripleInterpolator(t *testing.T) {
	src := "val q = s\"\"\"SELECT * FROM t\nWHERE id = ${userId}\"\"\"\nval after = 1"
	if k := kindOfSubstring(t, LangScala, src, `SELECT * FROM t`); k != KindString {
		t.Errorf("triple interpolator literal run should be string, got %v", k)
	}
	// The `${` marker is string; the inner expression `userId` is code.
	if k := kindOfSubstring(t, LangScala, src, `userId`); k != KindCode {
		t.Errorf("`${userId}` inner expression in a triple interpolator should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `after`); k != KindCode {
		t.Errorf("code after a triple interpolator should be code, got %v", k)
	}
}

// TestScalaSymbolLiteralIsCode is the headline gotcha: a leading `'` followed by
// an identifier NOT closed by `'` is a Scala SYMBOL literal (`'foo`), which must
// be CODE — it must NOT be lexed as a runaway char literal that swallows the
// rest of the line.
func TestScalaSymbolLiteralIsCode(t *testing.T) {
	src := "val sym = 'foo\nval SECRET = 1"
	if k := kindOfSubstring(t, LangScala, src, `foo`); k != KindCode {
		t.Errorf("a Scala Symbol literal 'foo must be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `SECRET`); k != KindCode {
		t.Errorf("code after a Symbol literal must not be swallowed as a char literal, got %v", k)
	}
}

// TestScalaCharLiteral: a genuine char literal `'x'` (and an escaped `'\”`) is
// string-kind, and the trailing code stays code.
func TestScalaCharLiteral(t *testing.T) {
	src := `val c = 'x' ; val SECRET = 1`
	if k := kindOfSubstring(t, LangScala, src, `'x'`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `SECRET`); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
	esc := `val n = '\'' ; val AFTER = 1`
	if k := kindOfSubstring(t, LangScala, esc, `AFTER`); k != KindCode {
		t.Errorf("code after an escaped char literal should be code, got %v", k)
	}
}

// TestScalaDoubleSlashInsideStringIsNotComment: a URL's `//` inside a string must
// not begin a comment.
func TestScalaDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `val url = "https://example.com/path" ; val SECRET = 1`
	if k := kindOfSubstring(t, LangScala, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangScala, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestScalaStraddleNotDataBlob guards the boundary contract: a span that begins
// in a string but leaks into code is not a clean string region.
func TestScalaStraddleNotDataBlob(t *testing.T) {
	src := `val x = "yy" + b`
	regions := Classify(LangScala, []byte(src))
	regionsCover(t, regions, len(src))
	strStart := indexOf(src, `"yy"`)
	if InDataBlob(LangScala, []byte(src), strStart+1, strStart+6) {
		t.Error("a span straddling string into code must not be reported as a data blob")
	}
}

// TestScalaDataBlobInTripleStringSuppressed proves the payoff: a long base64/
// data-URI payload inside a Scala triple string is a blob (suppressed), while a
// short secret in an ordinary string is NOT (kept).
func TestScalaDataBlobInTripleStringSuppressed(t *testing.T) {
	longBlob := "val icon = \"\"\"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\"\"\""
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangScala, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI triple-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`val apiKey = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangScala, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Scala string must NOT be a data blob")
	}
}

// TestScalaSuppressNonCodePolicy mirrors the Go/C# policy tests: a comment match
// and a data-blob-string match are dropped by SuppressNonCode, while a short
// ordinary-string secret is kept.
func TestScalaSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("val x = 1 // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangScala, comment, k, k+32) {
		t.Error("a token inside a Scala comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`val key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangScala, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Scala string literal must NOT be suppressed")
	}
}
