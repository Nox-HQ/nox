package lexctx

import "testing"

// TestScanCSharp exercises the headline C# lexical roles the same way
// TestScanGo / TestScanPython do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and AI analyzers (and the C#
// taint extractor) rely on when reasoning about C# source.
func TestScanCSharp(t *testing.T) {
	src := "var apiKey = \"s3cr3t\";\n" +
		"// line comment s3cr3t\n" +
		"/// doc s3cr3t comment\n" +
		"/* block s3cr3t comment */\n" +
		"var verb = @\"C:\\s3cr3t\\path\";\n" +
		"var interp = $\"hello s3cr3t\";\n" +
		"char c = 's';\n"
	if k := kindOfSubstring(t, LangCSharp, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `"s3cr3t"`); k != KindString {
		t.Errorf("string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `doc s3cr3t comment`); k != KindComment {
		t.Errorf("/// doc comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `C:\s3cr3t\path`); k != KindString {
		t.Errorf("verbatim string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `hello s3cr3t`); k != KindString {
		t.Errorf("interpolated string body should be string, got %v", k)
	}
}

func TestCSharpLangFromPath(t *testing.T) {
	if got := LangFromPath("src/Controllers/Home.cs"); got != LangCSharp {
		t.Errorf("LangFromPath(.cs) = %v, want %v", got, LangCSharp)
	}
	if got := LangFromPath("PROG.CS"); got != LangCSharp {
		t.Errorf("LangFromPath is not case-insensitive for .cs, got %v", got)
	}
}

func TestCSharpLangString(t *testing.T) {
	if got := LangCSharp.String(); got != "csharp" {
		t.Errorf("LangCSharp.String() = %q, want %q", got, "csharp")
	}
}

// TestCSharpLineComment: a `//` runs to end of line; the following line is code.
func TestCSharpLineComment(t *testing.T) {
	src := "int x = 1; // comment SECRET here\nint y = 2;"
	if k := kindOfSubstring(t, LangCSharp, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `int y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestCSharpDocComment: `///` is a documentation line comment, still a comment;
// the following line is code.
func TestCSharpDocComment(t *testing.T) {
	src := "/// <summary>SECRET</summary>\nint y = 2;"
	if k := kindOfSubstring(t, LangCSharp, src, `<summary>SECRET`); k != KindComment {
		t.Errorf("/// doc-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `int y = 2`); k != KindCode {
		t.Errorf("code after a doc comment should be code, got %v", k)
	}
}

// TestCSharpBlockCommentSpansLines: `/* ... */` crosses newlines; C# block
// comments do NOT nest, so the FIRST `*/` closes it and the rest is code.
func TestCSharpBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangCSharp, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestCSharpInterpretedEscapedQuote: `\"` must not close the ordinary string, so
// the trailing code stays code.
func TestCSharpInterpretedEscapedQuote(t *testing.T) {
	src := `var s = "a\"b"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestCSharpInterpretedStringEndsAtNewline: an unterminated ordinary string is
// closed by the newline so the next line's code is not swallowed.
func TestCSharpInterpretedStringEndsAtNewline(t *testing.T) {
	src := "var s = \"unterminated\nvar SECRET = 1;"
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestCSharpVerbatimStringSpansLines: `@"..."` processes NO backslash escapes (a
// `\` is literal), CAN span newlines, and `""` is a literal quote (not a close).
// A base64/data-URI blob is often a verbatim string. The `//` and `\` inside
// must not be mis-scanned and the trailing code stays code.
func TestCSharpVerbatimStringSpansLines(t *testing.T) {
	src := "var blob = @\"line1 // not a comment\nC:\\not\\escaped and \"\"quoted\"\" SECRET\";\nvar after = 1;"
	if k := kindOfSubstring(t, LangCSharp, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a verbatim string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `C:\not\escaped`); k != KindString {
		t.Errorf("`\\` inside a verbatim string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `quoted`); k != KindString {
		t.Errorf("`\"\"` doubled quote inside verbatim must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `after`); k != KindCode {
		t.Errorf("code after a multi-line verbatim string should be code, got %v", k)
	}
}

// TestCSharpVerbatimBackslashNoEscape: a backslash in a verbatim string is
// literal and does NOT escape the closing quote — the string ends at the first
// undoubled quote.
func TestCSharpVerbatimBackslashNoEscape(t *testing.T) {
	src := `var r = @"a\"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET`); k != KindCode {
		t.Errorf("code after a verbatim string with a trailing backslash should be code, got %v", k)
	}
}

// TestCSharpInterpolatedString: `$"..."` honors backslash escapes like an
// ordinary string; the body is string-kind and following code stays code.
func TestCSharpInterpolatedString(t *testing.T) {
	src := `var s = $"user {name} SECRETVAL"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangCSharp, src, `SECRETVAL`); k != KindString {
		t.Errorf("interpolated string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET =`); k != KindCode {
		t.Errorf("code after an interpolated string should be code, got %v", k)
	}
}

// TestCSharpInterpolatedVerbatim: both `$@"..."` and `@$"..."` are
// interpolated-verbatim strings: no escapes, `""` is a literal quote, spans
// lines.
func TestCSharpInterpolatedVerbatim(t *testing.T) {
	for _, prefix := range []string{`$@`, `@$`} {
		src := "var s = " + prefix + "\"C:\\a {x} SECRETVAL\"; var SECRET = 1;"
		if k := kindOfSubstring(t, LangCSharp, src, `SECRETVAL`); k != KindString {
			t.Errorf("%s interpolated-verbatim body should be string, got %v", prefix, k)
		}
		if k := kindOfSubstring(t, LangCSharp, src, `SECRET =`); k != KindCode {
			t.Errorf("%s: code after interpolated-verbatim string should be code, got %v", prefix, k)
		}
	}
}

// TestCSharpRawStringLiteral: `"""..."""` (C# 11) is a multi-line raw string;
// interior double quotes and `//` are literal, and the trailing code stays code.
func TestCSharpRawStringLiteral(t *testing.T) {
	src := "var j = \"\"\"\n{ \"key\": \"val\" } // SECRET inside\n\"\"\";\nvar after = 1;"
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET inside`); k != KindString {
		t.Errorf("raw-string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `after`); k != KindCode {
		t.Errorf("code after a raw string literal should be code, got %v", k)
	}
}

// TestCSharpCharLiteral: char literals `'x'` carry escapes; an escaped quote
// must not be misread and the trailing code stays code.
func TestCSharpCharLiteral(t *testing.T) {
	src := `char c = '\''; var SECRET = 1;`
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET`); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `'\''`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
}

// TestCSharpDoubleSlashInsideStringIsNotComment: a URL's `//` inside an ordinary
// string must not begin a comment.
func TestCSharpDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `var url = "https://example.com/path"; var SECRET = 1;`
	if k := kindOfSubstring(t, LangCSharp, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCSharp, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestCSharpStraddleNotDataBlob guards the boundary contract: a span that begins
// in a string but leaks into code is not a clean string region.
func TestCSharpStraddleNotDataBlob(t *testing.T) {
	src := `var x = "yy" + b;`
	regions := Classify(LangCSharp, []byte(src))
	regionsCover(t, regions, len(src))
	strStart := indexOf(src, `"yy"`)
	if InDataBlob(LangCSharp, []byte(src), strStart+1, strStart+6) {
		t.Error("a span straddling string into code must not be reported as a data blob")
	}
}

// TestCSharpDataBlobInVerbatimSuppressed proves the payoff: a long base64/
// data-URI payload inside a C# verbatim string is a blob (suppressed), while a
// short secret in an ordinary string is NOT (kept).
func TestCSharpDataBlobInVerbatimSuppressed(t *testing.T) {
	longBlob := "var icon = @\"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\";"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangCSharp, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI verbatim-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`var apiKey = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangCSharp, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary C# string must NOT be a data blob")
	}
}

// TestCSharpSuppressNonCodePolicy mirrors the Go/Python policy tests: a comment
// match and a data-blob-string match are dropped by SuppressNonCode, while a
// short ordinary-string secret is kept.
func TestCSharpSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("int x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangCSharp, comment, k, k+32) {
		t.Error("a token inside a C# comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`var key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangCSharp, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a C# string literal must NOT be suppressed")
	}
}
