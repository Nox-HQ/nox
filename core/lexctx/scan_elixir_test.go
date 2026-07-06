package lexctx

import "testing"

// TestScanElixir exercises the headline Elixir lexical roles the same way
// TestScanRuby / TestScanGo do: one fixture, one needle per role. It pins the
// code/string/comment classification the SAST analyzers rely on for Elixir.
func TestScanElixir(t *testing.T) {
	src := "api_key = \"s3cr3t\"\n" +
		"# line comment s3cr3t\n" +
		"charlist = 'plain s3cr3t'\n" +
		"word = ~w(alpha s3cr3t gamma)\n" +
		"code = 1 + 2\n"
	if k := kindOfSubstring(t, LangElixir, src, `api_key`); k != KindCode {
		t.Errorf("api_key should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `'plain s3cr3t'`); k != KindString {
		t.Errorf("charlist literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `alpha s3cr3t gamma`); k != KindString {
		t.Errorf("~w() sigil body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `code = 1 + 2`); k != KindCode {
		t.Errorf("plain code should be code, got %v", k)
	}
}

func TestElixirLangFromPath(t *testing.T) {
	if got := LangFromPath("lib/app/user.ex"); got != LangElixir {
		t.Errorf("LangFromPath(.ex) = %v, want %v", got, LangElixir)
	}
	if got := LangFromPath("test/user_test.exs"); got != LangElixir {
		t.Errorf("LangFromPath(.exs) = %v, want %v", got, LangElixir)
	}
	if got := LangFromPath("mix.EXS"); got != LangElixir {
		t.Errorf("LangFromPath is not case-insensitive for .exs, got %v", got)
	}
}

func TestElixirLangString(t *testing.T) {
	if got := LangElixir.String(); got != "elixir" {
		t.Errorf("LangElixir.String() = %q, want %q", got, "elixir")
	}
}

// TestElixirLineComment: a `#` runs to end of line; the following line is code.
// Elixir has NO block comments, so a `#` is always a line comment in code
// context.
func TestElixirLineComment(t *testing.T) {
	src := "x = 1 # comment SECRET here\ny = 2"
	if k := kindOfSubstring(t, LangElixir, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestElixirDoubleQuoteInterpolation: the `#{ ... }` fields of a double-quoted
// string are CODE — a tainted value spliced via "SELECT #{q}" lives in a real
// expression — while the surrounding literal stays string.
func TestElixirDoubleQuoteInterpolation(t *testing.T) {
	src := "q = \"SELECT #{user_input} FROM t\"\nSECRET = 1"
	if k := kindOfSubstring(t, LangElixir, src, `user_input`); k != KindCode {
		t.Errorf("#{} interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `SELECT `); k != KindString {
		t.Errorf("literal part of the string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestElixirCharlistNoInterpolation: single-quoted charlists interpolate too in
// Elixir, but we treat the `#{...}` field the same as a string. A plain charlist
// with no interpolation is entirely string.
func TestElixirCharlistNoInterpolation(t *testing.T) {
	src := "c = 'no interp here'\nSECRET = 1"
	if k := kindOfSubstring(t, LangElixir, src, `no interp here`); k != KindString {
		t.Errorf("charlist body should stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a charlist should be code, got %v", k)
	}
}

// TestElixirEscapedQuote: a `\"` must not close a double-quoted string, so the
// trailing code stays code.
func TestElixirEscapedQuote(t *testing.T) {
	src := `s = "a\"b"; SECRET = 1`
	if k := kindOfSubstring(t, LangElixir, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestElixirHeredoc: a `"""..."""` heredoc body is a string spanning lines; code
// after the closing delimiter is code.
func TestElixirHeredoc(t *testing.T) {
	src := "sql = \"\"\"\nSELECT SECRET FROM users\nWHERE 1=1\n\"\"\"\nafter = 1"
	if k := kindOfSubstring(t, LangElixir, src, `SELECT SECRET FROM users`); k != KindString {
		t.Errorf("heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `after = 1`); k != KindCode {
		t.Errorf("code after a heredoc terminator should be code, got %v", k)
	}
}

// TestElixirCharlistHeredoc: a `”'...”'` charlist heredoc body is string.
func TestElixirCharlistHeredoc(t *testing.T) {
	src := "doc = '''\nBLOB line SECRET\n'''\nafter = 1"
	if k := kindOfSubstring(t, LangElixir, src, `BLOB line SECRET`); k != KindString {
		t.Errorf("charlist heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `after = 1`); k != KindCode {
		t.Errorf("code after a charlist heredoc should be code, got %v", k)
	}
}

// TestElixirSigilLowercaseInterp: a lowercase `~s(...)` sigil interpolates, so a
// `#{...}` field is code while the literal text stays string.
func TestElixirSigilLowercaseInterp(t *testing.T) {
	src := "a = ~s(id=#{user_var})\nSECRET = 1"
	if k := kindOfSubstring(t, LangElixir, src, `user_var`); k != KindCode {
		t.Errorf("~s() interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a ~s() sigil should be code, got %v", k)
	}
}

// TestElixirSigilUppercaseNoInterp: an uppercase `~S(...)` sigil does NOT
// interpolate, so a `#{...}` inside it stays literal string.
func TestElixirSigilUppercaseNoInterp(t *testing.T) {
	src := "a = ~S(id=#{not_code})\nSECRET = 1"
	if k := kindOfSubstring(t, LangElixir, src, `not_code`); k != KindString {
		t.Errorf("~S() (non-interpolating) #{} must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a ~S() sigil should be code, got %v", k)
	}
}

// TestElixirSigilRegex: a `~r/.../ ` regex sigil body is string-kind.
func TestElixirSigilRegex(t *testing.T) {
	src := "re = ~r/SECRET.*/\nafter = 1"
	if k := kindOfSubstring(t, LangElixir, src, `SECRET.*`); k != KindString {
		t.Errorf("~r// regex sigil body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangElixir, src, `after = 1`); k != KindCode {
		t.Errorf("code after a regex sigil should be code, got %v", k)
	}
}

// TestElixirCharCode: a `?c` character code is code (a literal integer), not a
// string. A `?"` must not open a string that swallows the line.
func TestElixirCharCode(t *testing.T) {
	src := "sep = ?\" \nSECRET = 1"
	if k := kindOfSubstring(t, LangElixir, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a ?\" char code should be code, got %v", k)
	}
	src2 := "nl = ?\\n\nSECRET = 2"
	if k := kindOfSubstring(t, LangElixir, src2, `SECRET = 2`); k != KindCode {
		t.Errorf("code after a ?\\n char code should be code, got %v", k)
	}
}

// TestElixirDataBlobSuppressed proves the payoff: a long base64/data-URI payload
// inside an Elixir heredoc is a blob (suppressed), while a short secret in an
// ordinary string is NOT (kept).
func TestElixirDataBlobSuppressed(t *testing.T) {
	longBlob := "icon = \"\"\"\ndata:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\n\"\"\"\n"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangElixir, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI heredoc blob must be reported as a data blob")
	}

	shortSecret := []byte(`api_key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangElixir, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Elixir string must NOT be a data blob")
	}
}

// TestElixirSuppressNonCodePolicy mirrors the Ruby/Go policy test: a comment
// match and a data-blob-string match are dropped by SuppressNonCode, while a
// short ordinary-string secret is kept.
func TestElixirSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("x = 1 # AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangElixir, comment, k, k+32) {
		t.Error("a token inside an Elixir comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangElixir, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an Elixir string literal must NOT be suppressed")
	}
}
