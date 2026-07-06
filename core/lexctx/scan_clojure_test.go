package lexctx

import "testing"

// TestScanClojure exercises the headline Clojure lexical roles the same way
// TestScanGo / TestScanPython do: one fixture, one needle per role. Clojure is a
// Lisp — `;` line comments, `"..."` strings (Java-style escapes), `#"..."` regex
// literals, and `\c` character literals — so the classifier must not misread a
// `\;` char as a comment or a `\"` char as a string opener.
func TestScanClojure(t *testing.T) {
	src := "(def api-key \"s3cr3t\")\n" +
		"; line comment s3cr3t\n" +
		"(re-find #\"s3cr3t-regex\" s)\n" +
		"(def ch \\c)\n" +
		"(def semi \\;)\n" +
		"(def qt \\\")\n"
	if k := kindOfSubstring(t, LangClojure, src, `def api-key`); k != KindCode {
		t.Errorf("def api-key should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `"s3cr3t"`); k != KindString {
		t.Errorf("string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `s3cr3t-regex`); k != KindString {
		t.Errorf("regex literal body should be string, got %v", k)
	}
}

func TestClojureLangFromPath(t *testing.T) {
	for _, ext := range []string{"src/app.clj", "src/app.cljs", "src/app.cljc", "resources/config.edn"} {
		if got := LangFromPath(ext); got != LangClojure {
			t.Errorf("LangFromPath(%q) = %v, want %v", ext, got, LangClojure)
		}
	}
	if got := LangFromPath("UPPER.CLJ"); got != LangClojure {
		t.Errorf("LangFromPath is not case-insensitive for .clj, got %v", got)
	}
}

func TestClojureLangString(t *testing.T) {
	if got := LangClojure.String(); got != "clojure" {
		t.Errorf("LangClojure.String() = %q, want %q", got, "clojure")
	}
}

// TestClojureLineComment: a `;` runs to end of line; the following line is code.
func TestClojureLineComment(t *testing.T) {
	src := "(foo 1) ; comment SECRET here\n(bar 2)"
	if k := kindOfSubstring(t, LangClojure, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `bar 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestClojureCharSemicolonNotComment pins the trickiest Clojure rule: `\;` is a
// character literal, NOT a comment start, so the code after it stays code.
func TestClojureCharSemicolonNotComment(t *testing.T) {
	src := `(def d \;) (def SECRET 1)`
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after a \\; char literal should be code (not swallowed by a comment), got %v", k)
	}
}

// TestClojureCharQuoteNotString pins that `\"` is a character literal, NOT a
// string opener — the code after it must not be swallowed as a string.
func TestClojureCharQuoteNotString(t *testing.T) {
	src := `(def q \") (def SECRET 1)`
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after a \\\" char literal should be code (not swallowed by a string), got %v", k)
	}
}

// TestClojureNamedCharLiterals: `\newline`, `\space`, `\tab` are char literals;
// the following code stays code (the scanner consumes the whole char name).
func TestClojureNamedCharLiterals(t *testing.T) {
	src := `(str \newline \space) (def SECRET 1)`
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after named char literals should be code, got %v", k)
	}
}

// TestClojureStringEscapedQuote: a `\"` INSIDE a string does not close it, so the
// trailing code stays code (Java-style escapes).
func TestClojureStringEscapedQuote(t *testing.T) {
	src := `(def s "a\"b") (def SECRET 1)`
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestClojureRegexLiteral: `#"..."` is a regex literal (string-kind). A backslash
// inside it escapes the next byte just like a string, so `\"` does not close it.
func TestClojureRegexLiteral(t *testing.T) {
	src := "(re-matches #\"a\\\"b\" x) (def SECRET 1)"
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after a regex literal should be code, got %v", k)
	}
}

// TestClojureStringSpansLines: Clojure strings CAN span newlines (unlike Go
// interpreted strings), which matters because a base64/data blob is often a
// multi-line string. The `;` and `#"` inside must not be mis-scanned.
func TestClojureStringSpansLines(t *testing.T) {
	src := "(def blob \"line1 ; not a comment\nline2 #\\\"not a regex\")\n(def after 1)"
	if k := kindOfSubstring(t, LangClojure, src, `; not a comment`); k != KindString {
		t.Errorf("`;` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangClojure, src, `after 1`); k != KindCode {
		t.Errorf("code after a multi-line string should be code, got %v", k)
	}
}

// TestClojureDiscardForm: `#_` discards the next form. At minimum the scanner must
// not break on it — the `#_` bytes and the form after stay code (best-effort:
// treating a discarded form as code is safe, it only forgoes suppression).
func TestClojureDiscardForm(t *testing.T) {
	src := `(list #_ignored 1 2) (def SECRET 1)`
	if k := kindOfSubstring(t, LangClojure, src, `SECRET`); k != KindCode {
		t.Errorf("code after a #_ discard form should be code, got %v", k)
	}
}

// TestClojureDataBlobInStringSuppressed proves the payoff: a long base64/data-URI
// payload inside a Clojure string is a blob (suppressed), while a short secret in
// an ordinary string is NOT (kept).
func TestClojureDataBlobInStringSuppressed(t *testing.T) {
	longBlob := "(def icon \"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\")"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangClojure, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI blob string must be reported as a data blob")
	}

	shortSecret := []byte(`(def api-key "AKIA1234567890ABCDEF1234567890AB")`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangClojure, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Clojure string must NOT be a data blob")
	}
}

// TestClojureSuppressNonCodePolicy mirrors the Go policy test for Clojure: a
// comment match is dropped by SuppressNonCode, while a short ordinary-string
// secret is kept.
func TestClojureSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("(foo 1) ; AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangClojure, comment, k, k+32) {
		t.Error("a token inside a Clojure comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`(def k "AKIA1234567890ABCDEF1234567890AB")`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangClojure, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Clojure string literal must NOT be suppressed")
	}
}
