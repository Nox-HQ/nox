package lexctx

import "testing"

// TestScanSwift exercises the headline Swift lexical roles the same way
// TestScanGo / TestScanCSharp do: one fixture, one needle per role. It pins the
// code/string/comment classification that the secrets and taint analyzers rely
// on when gating findings in Swift source.
func TestScanSwift(t *testing.T) {
	src := "let apiKey = \"s3cr3t\"\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"let raw = #\"template s3cr3t line\"#\n" +
		"let multi = \"\"\"\nblock s3cr3t body\n\"\"\"\n"
	if k := kindOfSubstring(t, LangSwift, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `"s3cr3t"`); k != KindString {
		t.Errorf("interpreted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `template s3cr3t line`); k != KindString {
		t.Errorf("raw string literal body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `block s3cr3t body`); k != KindString {
		t.Errorf("multiline string body should be string, got %v", k)
	}
}

func TestSwiftLangFromPath(t *testing.T) {
	if got := LangFromPath("Sources/App/routes.swift"); got != LangSwift {
		t.Errorf("LangFromPath(.swift) = %v, want %v", got, LangSwift)
	}
	if got := LangFromPath("UPPER.SWIFT"); got != LangSwift {
		t.Errorf("LangFromPath is not case-insensitive for .swift, got %v", got)
	}
}

func TestSwiftLangString(t *testing.T) {
	if got := LangSwift.String(); got != "swift" {
		t.Errorf("LangSwift.String() = %q, want %q", got, "swift")
	}
}

// TestSwiftLineComment: a `//` runs to end of line; the following line is code.
func TestSwiftLineComment(t *testing.T) {
	src := "let x = 1 // comment SECRET here\nlet y = 2"
	if k := kindOfSubstring(t, LangSwift, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `let y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestSwiftBlockCommentNested pins the NESTING rule (unlike Go/C): an inner `/*`
// opens a nested comment whose `*/` does NOT close the outer one — only the
// matching outer `*/` does, so the trailing `SECRET` is code.
func TestSwiftBlockCommentNested(t *testing.T) {
	src := "/* outer /* inner */ still comment SECRET */ CODE = 1"
	if k := kindOfSubstring(t, LangSwift, src, `inner`); k != KindComment {
		t.Errorf("inner nested comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `still comment SECRET`); k != KindComment {
		t.Errorf("text after the inner close but before the outer close must stay comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `CODE`); k != KindCode {
		t.Errorf("code after the matching outer `*/` should be code, got %v", k)
	}
}

// TestSwiftBlockCommentSpansLines: `/* ... */` crosses newlines.
func TestSwiftBlockCommentSpansLines(t *testing.T) {
	src := "before\n/* multi\n line SECRET\n comment */\nafter"
	if k := kindOfSubstring(t, LangSwift, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestSwiftInterpretedEscapedQuote: `\"` must not close the interpreted string.
func TestSwiftInterpretedEscapedQuote(t *testing.T) {
	src := `let s = "a\"b" ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestSwiftStringInterpolation: `\(expr)` is an interpolation hole whose CONTENTS
// are emitted as CODE — a tainted value spliced via "id=\(userInput)" lives in a
// real expression the taint engine must see (the dominant SQL/command-injection
// carrier in Swift). The surrounding literal text stays string, and crucially the
// `)` of the hole must not be mistaken for the string's close.
func TestSwiftStringInterpolation(t *testing.T) {
	src := `let s = "hi \(name) and \(other)" ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `name`); k != KindCode {
		t.Errorf("interpolation hole contents should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `other`); k != KindCode {
		t.Errorf("second interpolation hole contents should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `hi `); k != KindString {
		t.Errorf("literal text between holes should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after an interpolated string should be code, got %v", k)
	}
}

// TestSwiftInterpolationParenBalance: a `)` INSIDE the interpolation expression
// (a nested call) must not close the hole prematurely, and the string still
// terminates at its real closing quote.
func TestSwiftInterpolationParenBalance(t *testing.T) {
	src := `let s = "x \(f(g(y))) z" ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `z"`); k != KindString {
		t.Errorf("tail of the string after a nested-paren hole should stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestSwiftMultilineString: `"""..."""` spans lines; interior `"` and `//` are
// literal. The trailing code stays code.
func TestSwiftMultilineString(t *testing.T) {
	src := "let s = \"\"\"\nline1 // not a comment\nline2 \"not a close\" SECRET\n\"\"\"\nlet after = 1"
	if k := kindOfSubstring(t, LangSwift, src, `// not a comment`); k != KindString {
		t.Errorf("`//` inside a multiline string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `not a close`); k != KindString {
		t.Errorf("a single `\"` inside a multiline string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `after`); k != KindCode {
		t.Errorf("code after a multiline string should be code, got %v", k)
	}
}

// TestSwiftRawStringNoEscape: a raw string `#"..."#` processes NO escapes — a
// backslash is a literal byte and does NOT escape the closing `"#`, and a
// single `"` inside stays literal.
func TestSwiftRawStringNoEscape(t *testing.T) {
	src := `let r = #"a\"b"# ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `a\"b`); k != KindString {
		t.Errorf("raw-string body (escapes are literal) should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after a raw string should be code, got %v", k)
	}
}

// TestSwiftRawStringMultiHash: `##"..."##` closes only on `"` followed by the
// SAME number of `#`s — an interior `"#` with too few hashes stays inside.
func TestSwiftRawStringMultiHash(t *testing.T) {
	src := `let r = ##"has "# inside"## ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `has "# inside`); k != KindString {
		t.Errorf("an interior `\"#` with too few hashes must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after a multi-hash raw string should be code, got %v", k)
	}
}

// TestSwiftRawStringInterpolation: raw strings interpolate with `\#(...)` (an
// extra `#` per opening hash). The interpolation is kept as string; the closing
// paren must not be read as code and the string ends at `"#`.
func TestSwiftRawStringInterpolation(t *testing.T) {
	src := `let r = #"hi \#(name) x"# ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `name`); k != KindCode {
		t.Errorf("raw-string interpolation hole contents should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after a raw string with interpolation should be code, got %v", k)
	}
}

// TestSwiftDoubleSlashInsideStringIsNotComment: a URL's `//` inside an ordinary
// string must not begin a comment.
func TestSwiftDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `let url = "https://example.com/path" ; let SECRET = 1`
	if k := kindOfSubstring(t, LangSwift, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangSwift, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestSwiftDataBlobInRawStringSuppressed proves the payoff: a long base64/data-URI
// payload inside a Swift raw string is a blob (suppressed), while a short secret
// in an ordinary string is NOT.
func TestSwiftDataBlobInRawStringSuppressed(t *testing.T) {
	longBlob := "let icon = #\"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\"#"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangSwift, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI raw-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`let apiKey = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangSwift, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Swift string must NOT be a data blob")
	}
}

// TestSwiftSuppressNonCodePolicy mirrors the Go/C# policy tests for Swift: a
// comment match and a data-blob-string match are dropped by SuppressNonCode,
// while a short ordinary-string secret is kept.
func TestSwiftSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("let x = 1 // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangSwift, comment, k, k+32) {
		t.Error("a token inside a Swift comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`let key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangSwift, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Swift string literal must NOT be suppressed")
	}
}

// TestSwiftRegionsCoverAndAscending guards the region-list contract on a mixed
// fixture: contiguous, gap-free, ascending coverage of the whole input.
func TestSwiftRegionsCoverAndAscending(t *testing.T) {
	src := "let a = \"s\"\n/* c /* n */ */\nlet b = #\"r\"#\nlet m = \"\"\"\nx\n\"\"\"\n"
	regions := Classify(LangSwift, []byte(src))
	regionsCover(t, regions, len(src))
}
