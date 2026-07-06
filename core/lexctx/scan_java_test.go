package lexctx

import "testing"

// TestScanJava exercises the headline Java lexical roles the same way
// TestScanGo / TestScanPython do: one fixture, one needle per role. It pins the
// code/string/comment classification that the secrets and AI analyzers rely on
// when gating findings in Java source.
func TestScanJava(t *testing.T) {
	src := "String apiKey = \"s3cr3t\";\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"/** javadoc s3cr3t */\n" +
		"char r = 's';\n"
	if k := kindOfSubstring(t, LangJava, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `"s3cr3t"`); k != KindString {
		t.Errorf("string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `javadoc s3cr3t`); k != KindComment {
		t.Errorf("javadoc comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `'s'`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
}

func TestJavaLangFromPath(t *testing.T) {
	if got := LangFromPath("src/main/java/com/example/Handler.java"); got != LangJava {
		t.Errorf("LangFromPath(.java) = %v, want %v", got, LangJava)
	}
	if got := LangFromPath("UPPER.JAVA"); got != LangJava {
		t.Errorf("LangFromPath is not case-insensitive for .java, got %v", got)
	}
}

func TestJavaLangString(t *testing.T) {
	if got := LangJava.String(); got != "java" {
		t.Errorf("LangJava.String() = %q, want %q", got, "java")
	}
}

// TestJavaLineComment: a `//` runs to end of line; the following line is code.
func TestJavaLineComment(t *testing.T) {
	src := "int x = 1; // comment SECRET here\nint y = 2;"
	if k := kindOfSubstring(t, LangJava, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `int y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestJavaBlockCommentSpansLines: `/* ... */` crosses newlines; Java block
// comments do NOT nest, so the FIRST `*/` closes it and the rest is code.
func TestJavaBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangJava, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestJavaJavadocSpansLines: a `/** ... */` javadoc comment is scanned exactly
// like a block comment (the extra opening `*` is comment body).
func TestJavaJavadocSpansLines(t *testing.T) {
	src := "/**\n * @param name SECRET\n */\nString after = x;"
	if k := kindOfSubstring(t, LangJava, src, `@param name SECRET`); k != KindComment {
		t.Errorf("javadoc body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `after`); k != KindCode {
		t.Errorf("code after a javadoc comment should be code, got %v", k)
	}
}

// TestJavaBlockCommentNotNested pins the non-nesting rule: the first `*/` ends
// the comment even though an inner `/*` appeared, so trailing `SECRET` is code.
func TestJavaBlockCommentNotNested(t *testing.T) {
	src := "/* outer /* inner */ int SECRET = 1;"
	if k := kindOfSubstring(t, LangJava, src, `inner`); k != KindComment {
		t.Errorf("bytes before the first close should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `SECRET`); k != KindCode {
		t.Errorf("bytes after the first `*/` should be code (no nesting), got %v", k)
	}
}

// TestJavaStringEscapedQuote: `\"` must not close the string, so the trailing
// code stays code.
func TestJavaStringEscapedQuote(t *testing.T) {
	src := `String s = "a\"b"; int SECRET = 1;`
	if k := kindOfSubstring(t, LangJava, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestJavaStringEndsAtNewline: an unterminated string is closed by the newline,
// so the next line's code is not swallowed.
func TestJavaStringEndsAtNewline(t *testing.T) {
	src := "String s = \"unterminated\nint SECRET = 1;"
	if k := kindOfSubstring(t, LangJava, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestJavaTextBlockSpansLines: a text block `"""..."""` spans newlines and its
// body — including a `//` and a `"` — must stay string; trailing code is code.
func TestJavaTextBlockSpansLines(t *testing.T) {
	src := "String q = \"\"\"\n" +
		"SELECT * FROM t // not a comment\n" +
		"WHERE name = \"not a string\" SECRET\n" +
		"\"\"\";\n" +
		"int after = 1;"
	if k := kindOfSubstring(t, LangJava, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a text block must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `not a string`); k != KindString {
		t.Errorf("`\"` inside a text block must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `after`); k != KindCode {
		t.Errorf("code after a multi-line text block should be code, got %v", k)
	}
}

// TestJavaCharLiteral: char literals `'x'` carry escapes; a `'` inside an escape
// must not be misread, and the trailing code stays code.
func TestJavaCharLiteral(t *testing.T) {
	src := `char c = '\''; int SECRET = 1;`
	if k := kindOfSubstring(t, LangJava, src, `SECRET`); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `'\''`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
}

// TestJavaDoubleSlashInsideStringIsNotComment: a URL's `//` inside a string must
// not begin a comment.
func TestJavaDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `String url = "https://example.com/path"; int SECRET = 1;`
	if k := kindOfSubstring(t, LangJava, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJava, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestJavaStraddleNotDataBlob guards the boundary contract: a span that begins
// in a string but leaks into code is not treated as a clean string region.
func TestJavaStraddleNotDataBlob(t *testing.T) {
	src := `String x = "yy" + b;`
	regions := Classify(LangJava, []byte(src))
	regionsCover(t, regions, len(src))
	strStart := indexOf(src, `"yy"`)
	if InDataBlob(LangJava, []byte(src), strStart+1, strStart+6) {
		t.Error("a span straddling string into code must not be reported as a data blob")
	}
}

// TestJavaDataBlobInTextBlockSuppressed proves the payoff: a long base64/data-URI
// payload inside a Java text block is a blob (suppressed), while a short secret
// in an ordinary string is NOT (kept). This is the whole point of the classifier
// for Java.
func TestJavaDataBlobInTextBlockSuppressed(t *testing.T) {
	longBlob := "String icon = \"\"\"\ndata:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\n\"\"\";"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangJava, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI text-block blob must be reported as a data blob")
	}

	shortSecret := []byte(`String apiKey = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangJava, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Java string must NOT be a data blob")
	}
}

// TestJavaSuppressNonCodePolicy mirrors the Go/Python policy test for Java: a
// comment match and a data-blob-string match are dropped by SuppressNonCode,
// while a short ordinary-string secret is kept.
func TestJavaSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("int x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangJava, comment, k, k+32) {
		t.Error("a token inside a Java comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`String key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangJava, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Java string literal must NOT be suppressed")
	}
}
