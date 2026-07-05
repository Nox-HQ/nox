package lexctx

import "testing"

// These tests cover the cases that break naive lexers — the exact scenarios
// that make regex-on-raw-text SAST noisy. Each asserts the lexical Kind at a
// specific needle so a regression in the scanner is caught precisely.

func TestPythonFStringInterpolationIsCode(t *testing.T) {
	// The interpolated expression is CODE; the literal text around it is string.
	src := `msg = f"prefix {user_secret} suffix"`
	if k := kindOfSubstring(t, LangPython, src, `prefix `); k != KindString {
		t.Errorf("f-string literal text should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `user_secret`); k != KindCode {
		t.Errorf("f-string {expr} should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, ` suffix`); k != KindString {
		t.Errorf("f-string trailing text should be string, got %v", k)
	}
}

func TestPythonFStringDoubleBraceIsLiteral(t *testing.T) {
	// `{{` is a literal brace, not an interpolation opener.
	src := `x = f"literal {{braces}} here"`
	if k := kindOfSubstring(t, LangPython, src, `literal `); k != KindString {
		t.Errorf("text before {{ should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `braces`); k != KindString {
		t.Errorf("text inside {{ }} should be string, got %v", k)
	}
}

func TestPythonFStringNestedString(t *testing.T) {
	// A `}` inside a nested string in the field must not close the field early:
	// the field is `{d["}"]}`; the closing `}` is the last one. The trailing
	// literal ` tail` after the field is still string.
	src := `v = f"a {d["}"]} tail"`
	if k := kindOfSubstring(t, LangPython, src, `d[`); k != KindCode {
		t.Errorf("f-string field expression should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, ` tail`); k != KindString {
		t.Errorf("literal after nested-string field should be string, got %v", k)
	}
}

func TestPythonRawStringBackslashDoesNotEscape(t *testing.T) {
	// In a raw string, `\"` does NOT escape the quote — the string ends at the
	// quote, and the following bytes are code.
	src := `p = r"a\" + SECRET`
	// The raw string is r"a\"  -> ends at the second quote (the one after \).
	if k := kindOfSubstring(t, LangPython, src, `SECRET`); k != KindCode {
		t.Errorf("code after raw string should be code, got %v", k)
	}
}

func TestPythonBytePrefixString(t *testing.T) {
	src := `data = b"AKIAsecretinbytes"`
	if k := kindOfSubstring(t, LangPython, src, `AKIAsecretinbytes`); k != KindString {
		t.Errorf("byte-string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `data`); k != KindCode {
		t.Errorf("assignment target should be code, got %v", k)
	}
}

func TestPythonHashInsideStringIsNotComment(t *testing.T) {
	src := `url = "http://x/#frag" ; SECRET = 1`
	if k := kindOfSubstring(t, LangPython, src, `#frag`); k != KindString {
		t.Errorf("'#' inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `SECRET`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

func TestPythonPrefixLetterNotMisreadInIdentifier(t *testing.T) {
	// `myfunc("x")` — the `f` in myfunc must NOT be read as an f-string prefix.
	src := `result = myf("literalvalue")`
	if k := kindOfSubstring(t, LangPython, src, `myf(`); k != KindCode {
		t.Errorf("identifier ending in f should stay code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `literalvalue`); k != KindString {
		t.Errorf("the actual string literal should be string, got %v", k)
	}
}

func TestJSTemplateInterpolationIsCode(t *testing.T) {
	src := "const u = `Bearer ${apiToken} end`;"
	if k := kindOfSubstring(t, LangJavaScript, src, `Bearer `); k != KindString {
		t.Errorf("template literal text should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `apiToken`); k != KindCode {
		t.Errorf("template ${expr} should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, ` end`); k != KindString {
		t.Errorf("template trailing text should be string, got %v", k)
	}
}

func TestJSNestedTemplate(t *testing.T) {
	// A template nested inside an interpolation: the inner literal is string,
	// the inner ${...} is code again.
	src := "const x = `a ${ `b ${c} d` } e`;"
	if k := kindOfSubstring(t, LangJavaScript, src, `a `); k != KindString {
		t.Errorf("outer template text should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `b `); k != KindString {
		t.Errorf("inner template text should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `${c}`); k != KindCode {
		t.Errorf("inner interpolation expression should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, ` e`); k != KindString {
		t.Errorf("outer trailing text should be string, got %v", k)
	}
}

func TestJSRegexLiteralNotComment(t *testing.T) {
	// `/=/` at an expression position is a regex; the `//`-looking bytes must
	// not start a comment, and the trailing code stays code.
	src := "const re = /ab\\/cd/g; const SECRET = 1;"
	if k := kindOfSubstring(t, LangJavaScript, src, `ab`); k != KindString {
		t.Errorf("regex body should be string-kind, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `SECRET`); k != KindCode {
		t.Errorf("code after regex literal should be code, got %v", k)
	}
}

func TestJSDivisionIsNotRegex(t *testing.T) {
	// After an identifier, `/` is division, not a regex — the rest of the line
	// stays code (not swallowed as a regex/string).
	src := "const r = width / height; const SECRET = 2;"
	if k := kindOfSubstring(t, LangJavaScript, src, `height`); k != KindCode {
		t.Errorf("division operand should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `SECRET`); k != KindCode {
		t.Errorf("code after division should be code, got %v", k)
	}
}

func TestJSDoubleSlashInsideStringIsNotComment(t *testing.T) {
	// A URL's `//` inside a string must not start a comment.
	src := `const url = "https://example.com/path"; const SECRET = 3;`
	if k := kindOfSubstring(t, LangJavaScript, src, `//example`); k != KindString {
		t.Errorf("'//' inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

func TestJSEscapedQuoteInString(t *testing.T) {
	src := `const s = "a\"b"; const SECRET = 4;`
	if k := kindOfSubstring(t, LangJavaScript, src, `SECRET`); k != KindCode {
		t.Errorf("code after escaped-quote string should be code, got %v", k)
	}
}

func TestJSBlockCommentSpansLines(t *testing.T) {
	src := "before;\n/* multi\n line SECRET\n comment */\nafter;"
	if k := kindOfSubstring(t, LangJavaScript, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `after`); k != KindCode {
		t.Errorf("code after block comment should be code, got %v", k)
	}
}

// TestClassifyIsDeterministic guards nox's determinism invariant: repeated
// classification of the same input yields byte-identical region lists.
func TestClassifyIsDeterministic(t *testing.T) {
	inputs := []struct {
		lang Lang
		src  string
	}{
		{LangPython, `x = f"a {b} c" # tail`},
		{LangJavaScript, "const x = `a ${b} c`; // tail"},
	}
	for _, in := range inputs {
		first := Classify(in.lang, []byte(in.src))
		for i := 0; i < 5; i++ {
			again := Classify(in.lang, []byte(in.src))
			if len(again) != len(first) {
				t.Fatalf("non-deterministic region count for %q", in.src)
			}
			for j := range first {
				if again[j] != first[j] {
					t.Fatalf("non-deterministic region %d for %q: %+v vs %+v",
						j, in.src, again[j], first[j])
				}
			}
		}
	}
}
