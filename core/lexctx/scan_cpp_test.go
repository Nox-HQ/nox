package lexctx

import "testing"

// TestScanCPP exercises the headline C/C++ lexical roles the same way the Go and
// C# scanner tests do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and AI analyzers rely on when
// gating findings in C/C++ source.
func TestScanCPP(t *testing.T) {
	src := "int apiKey = 0; // s3cr3t line comment\n" +
		"const char* k = \"s3cr3t\";\n" +
		"/* block s3cr3t comment */\n" +
		"const wchar_t* w = L\"wide s3cr3t\";\n" +
		"const char* r = R\"(raw s3cr3t line)\";\n" +
		"char c = 's';\n"

	cases := []struct {
		name   string
		needle string
		want   Kind
	}{
		{"identifier is code", "apiKey", KindCode},
		{"line comment", "s3cr3t line comment", KindComment},
		{"ordinary string", `"s3cr3t"`, KindString},
		{"block comment", "block s3cr3t comment", KindComment},
		{"wide string prefix L body", `"wide s3cr3t"`, KindString},
		{"raw string R\"(...)\" body", `raw s3cr3t line`, KindString},
		{"char literal", "'s'", KindString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if k := kindOfSubstring(t, LangCPP, src, tc.needle); k != tc.want {
				t.Errorf("%s: got %v, want %v", tc.name, k, tc.want)
			}
		})
	}
}

func TestCPPLangFromPath(t *testing.T) {
	for _, ext := range []string{
		"main.c", "lib.h", "app.cc", "widget.cpp", "engine.cxx",
		"types.hpp", "util.hh", "detail.hxx",
	} {
		if got := LangFromPath(ext); got != LangCPP {
			t.Errorf("LangFromPath(%q) = %v, want LangCPP", ext, got)
		}
	}
	if got := LangFromPath("UPPER.CPP"); got != LangCPP {
		t.Errorf("LangFromPath is not case-insensitive for .cpp, got %v", got)
	}
}

func TestCPPLangString(t *testing.T) {
	if got := LangCPP.String(); got != "cpp" {
		t.Errorf("LangCPP.String() = %q, want %q", got, "cpp")
	}
}

// TestCPPLineComment: a `//` runs to end of line; the following line is code.
func TestCPPLineComment(t *testing.T) {
	src := "int x = 1; // comment SECRET here\nint y = 2;"
	if k := kindOfSubstring(t, LangCPP, src, "comment SECRET here"); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int y = 2;"); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestCPPLineCommentSplice: a `\`-newline continues a line comment onto the next
// physical line (C/C++ line-continuation), so the spliced text stays comment.
func TestCPPLineCommentSplice(t *testing.T) {
	src := "int x = 1; // comment continues \\\nSECRET still comment\nint y = 2;"
	if k := kindOfSubstring(t, LangCPP, src, "SECRET still comment"); k != KindComment {
		t.Errorf("spliced line-comment continuation should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int y = 2;"); k != KindCode {
		t.Errorf("code after a spliced line comment should be code, got %v", k)
	}
}

// TestCPPBlockCommentSpansLines: `/* ... */` crosses newlines and does NOT nest.
func TestCPPBlockCommentSpansLines(t *testing.T) {
	src := "before;\n/* multi\n line SECRET\n comment */\nafter;"
	if k := kindOfSubstring(t, LangCPP, src, "line SECRET"); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "after;"); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestCPPBlockCommentNotNested pins the non-nesting rule.
func TestCPPBlockCommentNotNested(t *testing.T) {
	src := "/* outer /* inner */ int SECRET = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "inner"); k != KindComment {
		t.Errorf("bytes before the first close should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "SECRET"); k != KindCode {
		t.Errorf("bytes after the first `*/` should be code (no nesting), got %v", k)
	}
}

// TestCPPStringEncodingPrefixes: L"...", u8"...", u"...", U"..." are all strings,
// and the code after them stays code.
func TestCPPStringEncodingPrefixes(t *testing.T) {
	for _, p := range []string{"L", "u8", "u", "U"} {
		src := "auto s = " + p + "\"payload SECRET\"; int after = 1;"
		if k := kindOfSubstring(t, LangCPP, src, "payload SECRET"); k != KindString {
			t.Errorf("%s-prefixed string body should be string, got %v", p, k)
		}
		if k := kindOfSubstring(t, LangCPP, src, "int after = 1;"); k != KindCode {
			t.Errorf("code after a %s-prefixed string should be code, got %v", p, k)
		}
	}
}

// TestCPPEscapedQuote: `\"` must not close the string, so trailing code is code.
func TestCPPEscapedQuote(t *testing.T) {
	src := `const char* s = "a\"b"; int SECRET = 1;`
	if k := kindOfSubstring(t, LangCPP, src, "SECRET"); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestCPPRawStringNoEscape: a raw string R"(...)" processes NO escapes and may
// contain `"`, `\`, and `//` inertly; the trailing code stays code.
func TestCPPRawStringNoEscape(t *testing.T) {
	src := "auto r = R\"(line1 // not a comment \"not a string\" \\ SECRET)\";\nint after = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "// not a comment"); k != KindString {
		t.Errorf("`//` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "not a string"); k != KindString {
		t.Errorf("`\"` inside a raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int after = 1;"); k != KindCode {
		t.Errorf("code after a raw string should be code, got %v", k)
	}
}

// TestCPPRawStringDelimiter: R"delim(...)delim" closes only on the matching
// `)delim"`, so an inner `)"` that is NOT the delimiter stays inside the string.
func TestCPPRawStringDelimiter(t *testing.T) {
	src := "auto r = R\"xy(body )\" still SECRET )xy\";\nint after = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "still SECRET"); k != KindString {
		t.Errorf("a non-delimiter `)\"` inside a delimited raw string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int after = 1;"); k != KindCode {
		t.Errorf("code after a delimited raw string should be code, got %v", k)
	}
}

// TestCPPRawStringSpansLines: a raw string crosses newlines.
func TestCPPRawStringSpansLines(t *testing.T) {
	src := "auto r = R\"(line1\nline2 SECRET\nline3)\";\nint after = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "line2 SECRET"); k != KindString {
		t.Errorf("multi-line raw string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int after = 1;"); k != KindCode {
		t.Errorf("code after a multi-line raw string should be code, got %v", k)
	}
}

// TestCPPCharLiteral: char literals carry escapes; a `'\”` must not be misread.
func TestCPPCharLiteral(t *testing.T) {
	src := `char c = '\''; int SECRET = 1;`
	if k := kindOfSubstring(t, LangCPP, src, "SECRET"); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, `'\''`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
}

// TestCPPDigitSeparatorApostrophe: a `'` digit separator in a numeric literal
// (1'000'000) must NOT open a char literal and swallow following code.
func TestCPPDigitSeparatorApostrophe(t *testing.T) {
	src := "long n = 1'000'000; int SECRET = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "SECRET"); k != KindCode {
		t.Errorf("code after a digit-separator numeric literal should be code, got %v", k)
	}
}

// TestCPPIncludeAngleHeader: an `#include <stdio.h>` angle header is not a
// string that swallows code, and its `/`-bearing path (`sys/socket.h`) does not
// begin a comment; the following code stays code.
func TestCPPIncludeAngleHeader(t *testing.T) {
	src := "#include <sys/socket.h>\nint SECRET = 1;"
	// The header name is classified as string; crucially the `/` in the path must
	// NOT start a comment, so the next line stays code.
	if k := kindOfSubstring(t, LangCPP, src, "int SECRET = 1;"); k != KindCode {
		t.Errorf("code after an #include <...> directive should be code, got %v", k)
	}
	// A `#include "local.h"` quoted header is an ordinary string; code follows.
	src2 := "#include \"local.h\"\nint AFTER = 2;"
	if k := kindOfSubstring(t, LangCPP, src2, "int AFTER = 2;"); k != KindCode {
		t.Errorf("code after an #include \"...\" directive should be code, got %v", k)
	}
}

// TestCPPDefineDirective: a `#define` line is code; a value that looks like a
// URL string inside it does not corrupt following-line classification.
func TestCPPDefineDirective(t *testing.T) {
	src := "#define BASE \"https://example.com/path\"\nint SECRET = 1;"
	if k := kindOfSubstring(t, LangCPP, src, "//example"); k != KindString {
		t.Errorf("`//` inside a #define string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "int SECRET = 1;"); k != KindCode {
		t.Errorf("code after a #define directive should be code, got %v", k)
	}
}

// TestCPPDoubleSlashInsideStringIsNotComment: a URL's `//` inside a string must
// not begin a comment.
func TestCPPDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := `const char* url = "https://example.com/path"; int SECRET = 1;`
	if k := kindOfSubstring(t, LangCPP, src, "//example"); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangCPP, src, "SECRET"); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestCPPStraddleNotDataBlob guards the boundary contract: a span that begins in
// a string but leaks into code is not treated as a clean string region.
func TestCPPStraddleNotDataBlob(t *testing.T) {
	src := `int x = "yy" + b;`
	regions := Classify(LangCPP, []byte(src))
	regionsCover(t, regions, len(src))
	strStart := indexOf(src, `"yy"`)
	if InDataBlob(LangCPP, []byte(src), strStart+1, strStart+6) {
		t.Error("a span straddling string into code must not be reported as a data blob")
	}
}

// TestCPPDataBlobInStringSuppressed proves the payoff: a long base64/data-URI
// payload inside a C++ raw string is a blob (suppressed), while a short secret in
// an ordinary string is NOT (kept).
func TestCPPDataBlobInStringSuppressed(t *testing.T) {
	longBlob := "const char* icon = R\"(data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==)\";"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangCPP, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI raw-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`const char* apiKey = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangCPP, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary C++ string must NOT be a data blob")
	}
}

// TestCPPSuppressNonCodePolicy mirrors the Go policy test for C/C++.
func TestCPPSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("int x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangCPP, comment, k, k+32) {
		t.Error("a token inside a C++ comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`const char* key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangCPP, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a C++ string literal must NOT be suppressed")
	}
}
