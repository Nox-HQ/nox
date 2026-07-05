package lexctx

import "testing"

// TestScanGo exercises the headline Go lexical roles the same way TestScanPython
// / TestScanJavaScript do: one fixture, one needle per role. It pins the
// code/string/comment classification that the secrets and AI analyzers rely on
// when gating findings in Go source.
func TestScanGo(t *testing.T) {
	src := "apiKey := \"s3cr3t\"\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"raw := `template s3cr3t line`\n" +
		"r := 's'\n"
	if k := kindOfSubstring(t, LangGo, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `"s3cr3t"`); k != KindString {
		t.Errorf("interpreted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, "`template s3cr3t line`"); k != KindString {
		t.Errorf("raw string literal should be string, got %v", k)
	}
}

func TestGoLangFromPath(t *testing.T) {
	if got := LangFromPath("core/analyzers/secrets/dedup.go"); got != LangGo {
		t.Errorf("LangFromPath(.go) = %v, want %v", got, LangGo)
	}
	if got := LangFromPath("UPPER.GO"); got != LangGo {
		t.Errorf("LangFromPath is not case-insensitive for .go, got %v", got)
	}
}

func TestGoLangString(t *testing.T) {
	if got := LangGo.String(); got != "go" {
		t.Errorf("LangGo.String() = %q, want %q", got, "go")
	}
}

// TestGoLineComment: a `//` runs to end of line; the following line is code.
func TestGoLineComment(t *testing.T) {
	src := "x := 1 // comment SECRET here\ny := 2"
	if k := kindOfSubstring(t, LangGo, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `y := 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestGoBlockCommentSpansLines: `/* ... */` crosses newlines; Go block comments
// do NOT nest, so the FIRST `*/` closes it and the rest is code.
func TestGoBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangGo, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

func TestGoBlockCommentSingleLine(t *testing.T) {
	src := "a := 1 /* inline SECRET */ ; b := 2"
	if k := kindOfSubstring(t, LangGo, src, `inline SECRET`); k != KindComment {
		t.Errorf("single-line block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `b := 2`); k != KindCode {
		t.Errorf("code after inline block comment should be code, got %v", k)
	}
}

// TestGoBlockCommentNotNested pins the non-nesting rule: the first `*/` ends the
// comment even though an inner `/*` appeared, so the trailing `SECRET` is code.
func TestGoBlockCommentNotNested(t *testing.T) {
	src := "/* outer /* inner */ SECRET := 1"
	if k := kindOfSubstring(t, LangGo, src, `inner`); k != KindComment {
		t.Errorf("bytes before the first close should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("bytes after the first `*/` should be code (no nesting), got %v", k)
	}
}

// TestGoInterpretedEscapedQuote: `\"` must not close the interpreted string, so
// the trailing code stays code.
func TestGoInterpretedEscapedQuote(t *testing.T) {
	src := `s := "a\"b" ; SECRET := 1`
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestGoInterpretedStringEndsAtNewline: an unterminated interpreted string is
// closed by the newline (Go spec), so the next line's code is not swallowed.
func TestGoInterpretedStringEndsAtNewline(t *testing.T) {
	src := "s := \"unterminated\nSECRET := 1"
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestGoRawStringSpansLines: raw strings use backticks, span newlines, and do
// NOT process escapes — a base64 blob is often a raw string. The `//` and `"`
// inside must not be mis-scanned, and the trailing code stays code.
func TestGoRawStringSpansLines(t *testing.T) {
	src := "blob := `line1 // not a comment\nline2 \"not a string\" SECRET`\nafter := 1"
	if k := kindOfSubstring(t, LangGo, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `not a string`); k != KindString {
		t.Errorf("`\"` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `after`); k != KindCode {
		t.Errorf("code after a multi-line raw string should be code, got %v", k)
	}
}

// TestGoRawStringNoEscape: a backslash in a raw string is literal and does NOT
// escape the closing backtick — the string ends at the first backtick.
func TestGoRawStringNoEscape(t *testing.T) {
	src := "r := `a\\` + SECRET"
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("code after a raw string with a trailing backslash should be code, got %v", k)
	}
}

// TestGoRuneLiteral: rune literals `'...'` carry escapes; a `'` inside an escape
// must not be misread. Crucially, a `'` that is really an apostrophe-shaped
// operator is not our concern here — Go has no such thing — but a rune with an
// escaped quote must be handled.
func TestGoRuneLiteral(t *testing.T) {
	src := `c := '\'' ; SECRET := 1`
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("code after a rune literal should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `'\''`); k != KindString {
		t.Errorf("rune literal should be string-kind, got %v", k)
	}
}

// TestGoDoubleSlashInsideStringIsNotComment: a URL's `//` inside an interpreted
// string must not begin a comment.
func TestGoDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `url := "https://example.com/path" ; SECRET := 1`
	if k := kindOfSubstring(t, LangGo, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangGo, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestGoStraddleIntoCodeIsNotSuppressed guards the boundary contract: a span
// that begins in a string but leaks into code is not treated as a clean string
// region (mirrors the InCode straddle rule the analyzers rely on).
func TestGoStraddleNotDataBlob(t *testing.T) {
	// code | string | code: `x := "yy" + b`
	src := `x := "yy" + b`
	regions := Classify(LangGo, []byte(src))
	regionsCover(t, regions, len(src))
	// The string literal "yy" starts at index 5.
	strStart := indexOf(src, `"yy"`)
	// A match that spans from inside the string into the following code is a
	// straddle: InDataBlob must keep it (return false).
	if InDataBlob(LangGo, []byte(src), strStart+1, strStart+6) {
		t.Error("a span straddling string into code must not be reported as a data blob")
	}
}

// TestGoDataBlobInRawStringSuppressed proves the payoff: a long base64/data-URI
// payload inside a Go raw string is a blob (suppressed), while a short secret in
// an ordinary interpreted string is NOT (kept). This is the whole point of the
// classifier for Go.
func TestGoDataBlobInRawStringSuppressed(t *testing.T) {
	longBlob := "var icon = `data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==`"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangGo, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI raw-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`apiKey := "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangGo, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Go string must NOT be a data blob")
	}
}

// TestGoSuppressNonCodePolicy mirrors the Python policy test for Go: a comment
// match and a data-blob-string match are dropped by SuppressNonCode, while a
// short ordinary-string secret is kept.
func TestGoSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("x := 1 // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangGo, comment, k, k+32) {
		t.Error("a token inside a Go comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`key := "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangGo, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Go string literal must NOT be suppressed")
	}
}
