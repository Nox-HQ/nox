package lexctx

import "testing"

// TestScanRust exercises the headline Rust lexical roles the same way
// TestScanGo does: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and AI analyzers rely on when
// gating findings in Rust source.
func TestScanRust(t *testing.T) {
	src := "let api_key = \"s3cr3t\";\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"let raw = r#\"template s3cr3t line\"#;\n" +
		"let c = 's';\n"
	if k := kindOfSubstring(t, LangRust, src, `api_key`); k != KindCode {
		t.Errorf("api_key should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `"s3cr3t"`); k != KindString {
		t.Errorf("interpreted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `template s3cr3t line`); k != KindString {
		t.Errorf("raw string literal should be string, got %v", k)
	}
}

func TestRustLangFromPath(t *testing.T) {
	if got := LangFromPath("src/main.rs"); got != LangRust {
		t.Errorf("LangFromPath(.rs) = %v, want %v", got, LangRust)
	}
	if got := LangFromPath("UPPER.RS"); got != LangRust {
		t.Errorf("LangFromPath is not case-insensitive for .rs, got %v", got)
	}
}

func TestRustLangString(t *testing.T) {
	if got := LangRust.String(); got != "rust" {
		t.Errorf("LangRust.String() = %q, want %q", got, "rust")
	}
}

// TestRustLineComment: a `//` runs to end of line; the following line is code.
func TestRustLineComment(t *testing.T) {
	src := "let x = 1; // comment SECRET here\nlet y = 2;"
	if k := kindOfSubstring(t, LangRust, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestRustDocComments: /// (outer) and //! (inner) doc comments are comments,
// same as a plain //.
func TestRustDocComments(t *testing.T) {
	src := "/// outer doc SECRET\n//! inner doc SECRET\nlet z = 3;"
	if k := kindOfSubstring(t, LangRust, src, `outer doc SECRET`); k != KindComment {
		t.Errorf("/// doc comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `inner doc SECRET`); k != KindComment {
		t.Errorf("//! doc comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let z = 3`); k != KindCode {
		t.Errorf("code after doc comments should be code, got %v", k)
	}
}

// TestRustNestedBlockComment is the headline Rust gotcha: unlike Go/C, Rust
// block comments NEST. An inner /* ... */ must be balanced; the FIRST */ does
// NOT close the outer comment. Everything up to the matching outer */ is a
// comment, and the code after it is code.
func TestRustNestedBlockComment(t *testing.T) {
	src := "/* outer /* inner SECRET */ still comment */ let after = 1;"
	if k := kindOfSubstring(t, LangRust, src, `inner SECRET`); k != KindComment {
		t.Errorf("nested block-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `still comment`); k != KindComment {
		t.Errorf("text after the inner */ but before the outer */ is still comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let after = 1`); k != KindCode {
		t.Errorf("code after the balanced outer */ should be code, got %v", k)
	}
}

// TestRustNestedBlockCommentSpansLines: nested block comments crossing newlines
// still balance depth correctly.
func TestRustNestedBlockCommentSpansLines(t *testing.T) {
	src := "/*\n outer SECRET\n /* inner SECRET\n */\n still outer SECRET\n*/\nlet done = true;"
	if k := kindOfSubstring(t, LangRust, src, `inner SECRET`); k != KindComment {
		t.Errorf("multiline nested comment inner should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `still outer SECRET`); k != KindComment {
		t.Errorf("multiline nested comment tail should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let done = true`); k != KindCode {
		t.Errorf("code after multiline nested comment should be code, got %v", k)
	}
}

// TestRustRawStringHash: r#"..."# raw strings process no escapes and terminate
// only on a `"` followed by the matching number of `#`. A bare `"` inside does
// NOT close it, so an embedded quote stays inside the string.
func TestRustRawStringHash(t *testing.T) {
	src := "let s = r#\"has \" quote SECRET inside\"#;\nlet code_after = 1;"
	if k := kindOfSubstring(t, LangRust, src, `has " quote SECRET inside`); k != KindString {
		t.Errorf("r#\"...\"# body (with embedded quote) should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let code_after = 1`); k != KindCode {
		t.Errorf("code after a raw string should be code, got %v", k)
	}
}

// TestRustRawStringMultiHash: r##"..."## needs TWO closing #; a `"#` inside
// (one hash) does not terminate it.
func TestRustRawStringMultiHash(t *testing.T) {
	src := "let s = r##\"contains \"# one-hash SECRET\"##;\nlet done = 1;"
	if k := kindOfSubstring(t, LangRust, src, `contains "# one-hash SECRET`); k != KindString {
		t.Errorf("r##\"...\"## body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let done = 1`); k != KindCode {
		t.Errorf("code after a multi-hash raw string should be code, got %v", k)
	}
}

// TestRustRawStringSpansLines: raw strings carry multi-line data blobs (the
// base64/data-URI FP carrier) — the whole span is one string region.
func TestRustRawStringSpansLines(t *testing.T) {
	src := "let blob = r#\"line1 SECRET\nline2 SECRET\nline3 SECRET\"#;\nlet after = 2;"
	if k := kindOfSubstring(t, LangRust, src, `line2 SECRET`); k != KindString {
		t.Errorf("raw string spanning lines should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let after = 2`); k != KindCode {
		t.Errorf("code after a multi-line raw string should be code, got %v", k)
	}
}

// TestRustByteAndRawByteStrings: b"..." byte strings and br#"..."# raw byte
// strings are strings.
func TestRustByteStrings(t *testing.T) {
	src := "let b = b\"byte SECRET\";\nlet rb = br#\"raw byte SECRET\"#;\nlet after = 3;"
	if k := kindOfSubstring(t, LangRust, src, `byte SECRET`); k != KindString {
		t.Errorf("byte string b\"...\" should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `raw byte SECRET`); k != KindString {
		t.Errorf("raw byte string br#\"...\"# should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let after = 3`); k != KindCode {
		t.Errorf("code after byte strings should be code, got %v", k)
	}
}

// TestRustCharLiteral: a char literal 'x' is a string-kind region; the code
// after it is code.
func TestRustCharLiteral(t *testing.T) {
	src := "let ch = 'x'; let n = 5;"
	if k := kindOfSubstring(t, LangRust, src, `'x'`); k != KindString {
		t.Errorf("char literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let n = 5`); k != KindCode {
		t.Errorf("code after a char literal should be code, got %v", k)
	}
}

// TestRustEscapedCharLiteral: an escaped-quote char literal and a newline char
// literal stay self-contained; a following string is not swallowed.
func TestRustEscapedCharLiteral(t *testing.T) {
	src := "let q = '\\''; let s = \"after SECRET\";"
	if k := kindOfSubstring(t, LangRust, src, `"after SECRET"`); k != KindString {
		t.Errorf("string after an escaped-quote char literal should be a string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let s =`); k != KindCode {
		t.Errorf("code between an escaped char literal and a string should be code, got %v", k)
	}
}

// TestRustLifetimeNotChar is the second headline gotcha: a `'` followed by an
// identifier and NOT closed by a matching `'` is a LIFETIME (`'a`), not a char
// literal. Mis-lexing it as an unterminated char would swallow the following
// code (and the `str` type, the `"` of the next string) into a bogus string
// region. `&'a str` must stay entirely code.
func TestRustLifetimeNotChar(t *testing.T) {
	src := "fn f<'a>(x: &'a str) -> &'a str { let key = \"real SECRET\"; x }"
	if k := kindOfSubstring(t, LangRust, src, `&'a str`); k != KindCode {
		t.Errorf("a lifetime 'a in &'a str must be code, not a char literal, got %v", k)
	}
	// The real string literal after the lifetimes must still be classified as a
	// string (proving the lifetime did not swallow it into a runaway char).
	if k := kindOfSubstring(t, LangRust, src, `"real SECRET"`); k != KindString {
		t.Errorf("string after lifetimes should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `let key =`); k != KindCode {
		t.Errorf("code after lifetimes should be code, got %v", k)
	}
}

// TestRustLifetimeInGenerics: a standalone lifetime in a generic bound
// (`<'a, T>`) followed by more code must not start a runaway char.
func TestRustLifetimeInGenerics(t *testing.T) {
	src := "struct S<'a> { name: &'a str } let after = \"SECRET\";"
	if k := kindOfSubstring(t, LangRust, src, `struct S<'a>`); k != KindCode {
		t.Errorf("generic lifetime declaration should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRust, src, `"SECRET"`); k != KindString {
		t.Errorf("string after a generic lifetime should be string, got %v", k)
	}
}

// TestRustDataBlobRawString: a long data-URI/base64 blob in a raw string is a
// string region and is recognized as a data blob by isStringBlob, so the
// secrets analyzer suppresses matches inside it.
func TestRustDataBlobRawString(t *testing.T) {
	blob := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	src := "const LOGO: &str = r#\"" + blob + "\"#;\n"
	if k := kindOfSubstring(t, LangRust, src, `iVBORw0KGgo`); k != KindString {
		t.Errorf("base64 blob in a raw string should be string, got %v", k)
	}
	if InDataBlob(LangRust, []byte(src), byteIndex(src, "iVBORw0KGgo"), byteIndex(src, "iVBORw0KGgo")+11) != true {
		t.Errorf("a data-URI base64 raw string should be recognized as a data blob")
	}
}

// byteIndex returns the byte offset of the first occurrence of needle in s, or
// -1. Small test helper mirroring strings.Index without importing strings here.
func byteIndex(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
