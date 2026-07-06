package lexctx

import "testing"

// TestScanKotlin exercises the headline Kotlin lexical roles the same way
// TestScanGo / TestScanJavaScript do: one fixture, one needle per role. It pins
// the code/string/comment classification the secrets and taint analyzers rely on
// when gating findings in Kotlin source.
func TestScanKotlin(t *testing.T) {
	src := "val apiKey = \"s3cr3t\"\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"val raw = \"\"\"template s3cr3t line\"\"\"\n" +
		"val r = 's'\n"
	if k := kindOfSubstring(t, LangKotlin, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `"s3cr3t"`); k != KindString {
		t.Errorf("interpreted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `template s3cr3t line`); k != KindString {
		t.Errorf("triple-quoted raw string should be string, got %v", k)
	}
}

func TestKotlinLangFromPath(t *testing.T) {
	if got := LangFromPath("app/src/Main.kt"); got != LangKotlin {
		t.Errorf("LangFromPath(.kt) = %v, want %v", got, LangKotlin)
	}
	if got := LangFromPath("build.gradle.kts"); got != LangKotlin {
		t.Errorf("LangFromPath(.kts) = %v, want %v", got, LangKotlin)
	}
	if got := LangFromPath("UPPER.KT"); got != LangKotlin {
		t.Errorf("LangFromPath is not case-insensitive for .kt, got %v", got)
	}
}

func TestKotlinLangString(t *testing.T) {
	if got := LangKotlin.String(); got != "kotlin" {
		t.Errorf("LangKotlin.String() = %q, want %q", got, "kotlin")
	}
}

// TestKotlinLineComment: a `//` runs to end of line; the following line is code.
func TestKotlinLineComment(t *testing.T) {
	src := "val x = 1 // comment SECRET here\nval y = 2"
	if k := kindOfSubstring(t, LangKotlin, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `val y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestKotlinBlockCommentNested pins the NESTING rule: unlike Go/C/Java, a Kotlin
// block comment nests, so the inner `*/` does NOT close the outer comment — only
// the matching outer `*/` does, and the trailing SECRET is then code.
func TestKotlinBlockCommentNested(t *testing.T) {
	src := "/* outer /* inner */ still comment */ SECRET_VAR = 1"
	if k := kindOfSubstring(t, LangKotlin, src, `inner`); k != KindComment {
		t.Errorf("bytes inside the nested comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `still comment`); k != KindComment {
		t.Errorf("bytes after the inner close but before the outer close must stay comment (nesting), got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET_VAR`); k != KindCode {
		t.Errorf("bytes after the matching outer `*/` should be code, got %v", k)
	}
}

// TestKotlinBlockCommentSpansLines: `/* ... */` crosses newlines.
func TestKotlinBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangKotlin, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestKotlinTemplateString: a `"..."` string with a `$var` / `${expr}` template
// is still one string region — the interpolation markers do not end the string,
// and the code after it stays code.
func TestKotlinTemplateString(t *testing.T) {
	src := "val q = \"SELECT * FROM t WHERE id = $id AND x = ${f(y)}\"\nval SECRET = 1"
	if k := kindOfSubstring(t, LangKotlin, src, `SELECT * FROM t`); k != KindString {
		t.Errorf("template string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET`); k != KindCode {
		t.Errorf("code after a template string should be code, got %v", k)
	}
}

// TestKotlinInterpretedEscapedQuote: `\"` must not close the string.
func TestKotlinInterpretedEscapedQuote(t *testing.T) {
	src := `val s = "a\"b" ; val SECRET = 1`
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestKotlinInterpretedStringEndsAtNewline: an unterminated ordinary string is
// closed by the newline so the next line's code is not swallowed.
func TestKotlinInterpretedStringEndsAtNewline(t *testing.T) {
	src := "val s = \"unterminated\nval SECRET = 1"
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestKotlinRawStringSpansLines: triple-quoted raw strings span newlines and do
// NOT process escapes — a base64 blob is often a raw string. The `//` and `"`
// inside must not be mis-scanned, and the trailing code stays code.
func TestKotlinRawStringSpansLines(t *testing.T) {
	src := "val blob = \"\"\"line1 // not a comment\nline2 \"not a close\" SECRET\"\"\"\nval after = 1"
	if k := kindOfSubstring(t, LangKotlin, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `not a close`); k != KindString {
		t.Errorf("a single `\"` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `after`); k != KindCode {
		t.Errorf("code after a multi-line raw string should be code, got %v", k)
	}
}

// TestKotlinCharLiteral: char literals `'x'` carry escapes; an escaped `'` must
// not be misread, and following code stays code.
func TestKotlinCharLiteral(t *testing.T) {
	src := `val c = '\'' ; val SECRET = 1`
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET`); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `'\''`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
}

// TestKotlinDoubleSlashInsideStringIsNotComment: a URL's `//` inside a string
// must not begin a comment.
func TestKotlinDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `val url = "https://example.com/path" ; val SECRET = 1`
	if k := kindOfSubstring(t, LangKotlin, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangKotlin, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestKotlinDataBlobInRawStringSuppressed proves the payoff: a long base64/
// data-URI payload inside a Kotlin triple-quoted raw string is a blob
// (suppressed), while a short secret in an ordinary string is NOT (kept).
func TestKotlinDataBlobInRawStringSuppressed(t *testing.T) {
	longBlob := "val icon = \"\"\"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\"\"\""
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangKotlin, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI raw-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`val apiKey = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangKotlin, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Kotlin string must NOT be a data blob")
	}
}

// TestKotlinSuppressNonCodePolicy: a comment match is dropped by SuppressNonCode
// while a short ordinary-string secret is kept.
func TestKotlinSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("val x = 1 // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangKotlin, comment, k, k+32) {
		t.Error("a token inside a Kotlin comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`val key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangKotlin, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Kotlin string literal must NOT be suppressed")
	}
}
