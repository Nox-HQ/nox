package lexctx

import "testing"

// TestScanRuby exercises the headline Ruby lexical roles the same way
// TestScanGo / TestScanPython do: one fixture, one needle per role. It pins the
// code/string/comment classification the SAST analyzers rely on for Ruby.
func TestScanRuby(t *testing.T) {
	src := "api_key = \"s3cr3t\"\n" +
		"# line comment s3cr3t\n" +
		"single = 'plain s3cr3t'\n" +
		"cmd = `echo s3cr3t`\n" +
		"sym = :s3cr3t\n"
	if k := kindOfSubstring(t, LangRuby, src, `api_key`); k != KindCode {
		t.Errorf("api_key should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `'plain s3cr3t'`); k != KindString {
		t.Errorf("single-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, "`echo s3cr3t`"); k != KindString {
		t.Errorf("backtick command string should be string, got %v", k)
	}
}

func TestRubyLangFromPath(t *testing.T) {
	if got := LangFromPath("app/models/user.rb"); got != LangRuby {
		t.Errorf("LangFromPath(.rb) = %v, want %v", got, LangRuby)
	}
	if got := LangFromPath("Rakefile.RAKE"); got != LangRuby {
		t.Errorf("LangFromPath is not case-insensitive for .rake, got %v", got)
	}
	if got := LangFromPath("Gemfile"); got != LangRuby {
		t.Errorf("LangFromPath(Gemfile) = %v, want %v", got, LangRuby)
	}
	if got := LangFromPath("some/dir/Gemfile"); got != LangRuby {
		t.Errorf("LangFromPath(path/Gemfile) = %v, want %v", got, LangRuby)
	}
}

func TestRubyLangString(t *testing.T) {
	if got := LangRuby.String(); got != "ruby" {
		t.Errorf("LangRuby.String() = %q, want %q", got, "ruby")
	}
}

// TestRubyLineComment: a `#` runs to end of line; the following line is code.
func TestRubyLineComment(t *testing.T) {
	src := "x = 1 # comment SECRET here\ny = 2"
	if k := kindOfSubstring(t, LangRuby, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestRubyBeginEndComment: a `=begin`/`=end` block (both at column 0) is a
// comment spanning many lines; code after `=end` is code.
func TestRubyBeginEndComment(t *testing.T) {
	src := "before = 1\n=begin\nblock SECRET line\nmore SECRET\n=end\nafter = 2"
	if k := kindOfSubstring(t, LangRuby, src, `block SECRET line`); k != KindComment {
		t.Errorf("=begin/=end block body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `after = 2`); k != KindCode {
		t.Errorf("code after =end should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `before = 1`); k != KindCode {
		t.Errorf("code before =begin should be code, got %v", k)
	}
}

// TestRubyBeginNotAtColumnZero: `=begin` must start at column 0 to open a block
// comment. Indented, it is not a comment (it is a syntax error in real Ruby, but
// the classifier must not swallow the rest of the file as comment).
func TestRubyBeginNotAtColumnZero(t *testing.T) {
	src := "x = 1\n  =begin not a comment\nSECRET = 2"
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 2`); k != KindComment {
		// Indented =begin does NOT open a block comment, so the following line
		// is code, not comment.
		if k == KindComment {
			t.Errorf("indented =begin must not open a block comment")
		}
	}
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 2`); k != KindCode {
		t.Errorf("code after an indented (non-)=begin should be code, got %v", k)
	}
}

// TestRubyDoubleQuoteInterpolation: the `#{ ... }` fields of a double-quoted
// string are CODE — a tainted value spliced via "id=#{params[:id]}" lives in a
// real expression — while the surrounding literal stays string.
func TestRubyDoubleQuoteInterpolation(t *testing.T) {
	src := "q = \"SELECT #{user_input} FROM t\"\nSECRET = 1"
	if k := kindOfSubstring(t, LangRuby, src, `user_input`); k != KindCode {
		t.Errorf("#{} interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `SELECT `); k != KindString {
		t.Errorf("literal part of the string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestRubySingleQuoteNoInterpolation: single-quoted strings do NOT interpolate,
// so a `#{...}` inside them is literal string, not code.
func TestRubySingleQuoteNoInterpolation(t *testing.T) {
	src := "q = 'no #{interp} here'\nSECRET = 1"
	if k := kindOfSubstring(t, LangRuby, src, `interp`); k != KindString {
		t.Errorf("#{} inside single quotes must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a single-quoted string should be code, got %v", k)
	}
}

// TestRubyEscapedQuote: a `\"` must not close a double-quoted string, so the
// trailing code stays code.
func TestRubyEscapedQuote(t *testing.T) {
	src := `s = "a\"b" ; SECRET = 1`
	if k := kindOfSubstring(t, LangRuby, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestRubyHeredocSquiggly: a `<<~SQL ... SQL` heredoc body is a string spanning
// lines; code after the terminator is code.
func TestRubyHeredocSquiggly(t *testing.T) {
	src := "sql = <<~SQL\n  SELECT SECRET FROM users\n  WHERE 1=1\nSQL\nafter = 1"
	if k := kindOfSubstring(t, LangRuby, src, `SELECT SECRET FROM users`); k != KindString {
		t.Errorf("heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `after = 1`); k != KindCode {
		t.Errorf("code after a heredoc terminator should be code, got %v", k)
	}
}

// TestRubyHeredocDash: a `<<-ID ... ID` heredoc allows an indented terminator.
func TestRubyHeredocDash(t *testing.T) {
	src := "text = <<-EOF\n  body BLOB line\n  EOF\nnext_line = 2"
	if k := kindOfSubstring(t, LangRuby, src, `body BLOB line`); k != KindString {
		t.Errorf("<<-EOF heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `next_line = 2`); k != KindCode {
		t.Errorf("code after an indented heredoc terminator should be code, got %v", k)
	}
}

// TestRubyPercentW: a `%w[...]` word array is string-kind, and code after it is
// code. It must not be confused with the modulo operator.
func TestRubyPercentW(t *testing.T) {
	src := "arr = %w[alpha SECRET gamma]\nafter = 1"
	if k := kindOfSubstring(t, LangRuby, src, `alpha SECRET gamma`); k != KindString {
		t.Errorf("%%w[] word-array body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `after = 1`); k != KindCode {
		t.Errorf("code after a %%w[] array should be code, got %v", k)
	}
}

// TestRubyModuloIsNotPercentLiteral: a `%` used as modulo must stay code and not
// begin a `%w`-style literal.
func TestRubyModuloIsNotPercentLiteral(t *testing.T) {
	src := "n = a % b\nSECRET = 1"
	if k := kindOfSubstring(t, LangRuby, src, `a % b`); k != KindCode {
		t.Errorf("modulo expression should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a modulo expression should be code, got %v", k)
	}
}

// TestRubyPercentQ: `%q(...)` (non-interpolating) and `%Q(...)` (interpolating)
// are string-kind.
func TestRubyPercentQ(t *testing.T) {
	src := "a = %q(single SECRET)\nb = %Q(double SECRET)\nafter = 1"
	if k := kindOfSubstring(t, LangRuby, src, `single SECRET`); k != KindString {
		t.Errorf("%%q() body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `double SECRET`); k != KindString {
		t.Errorf("%%Q() body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `after = 1`); k != KindCode {
		t.Errorf("code after %%q/%%Q should be code, got %v", k)
	}
}

// TestRubyPercentQInterpolation: an interpolating `%Q(...)` emits its `#{}`
// field as code while the surrounding literal stays string; a non-interpolating
// `%q(...)` keeps `#{}` as literal string.
func TestRubyPercentQInterpolation(t *testing.T) {
	src := "a = %Q(id=#{user_var})\nb = %q(id=#{not_code})\nSECRET = 1"
	if k := kindOfSubstring(t, LangRuby, src, `user_var`); k != KindCode {
		t.Errorf("%%Q interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `not_code`); k != KindString {
		t.Errorf("%%q (non-interpolating) #{} must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after percent literals should be code, got %v", k)
	}
}

// TestRubyDataBlobInHeredocSuppressed proves the payoff: a long base64/data-URI
// payload inside a Ruby heredoc is a blob (suppressed), while a short secret in
// an ordinary string is NOT (kept).
func TestRubyDataBlobInHeredocSuppressed(t *testing.T) {
	longBlob := "icon = <<~DATA\ndata:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\nDATA\n"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangRuby, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI heredoc blob must be reported as a data blob")
	}

	shortSecret := []byte(`api_key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangRuby, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Ruby string must NOT be a data blob")
	}
}

// TestRubySuppressNonCodePolicy mirrors the Go/Python policy test: a comment
// match and a data-blob-string match are dropped by SuppressNonCode, while a
// short ordinary-string secret is kept.
func TestRubySuppressNonCodePolicy(t *testing.T) {
	comment := []byte("x = 1 # AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangRuby, comment, k, k+32) {
		t.Error("a token inside a Ruby comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangRuby, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Ruby string literal must NOT be suppressed")
	}
}

// TestRubyRegexNotDivision: a `/.../ ` regex literal is string-kind; a `/` used
// as division stays code. The classifier uses a preceding-token heuristic.
func TestRubyRegexNotDivision(t *testing.T) {
	// Regex after `=` (an operator position): the /.../ is a regex literal.
	src := "m = /SECRET.*/\nafter = 1"
	if k := kindOfSubstring(t, LangRuby, src, `SECRET.*`); k != KindString {
		t.Errorf("regex literal body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangRuby, src, `after = 1`); k != KindCode {
		t.Errorf("code after a regex literal should be code, got %v", k)
	}
}

// TestRubyDivisionIsCode: a `/` between two operands (division) must stay code,
// not open a regex that swallows the rest of the line.
func TestRubyDivisionIsCode(t *testing.T) {
	src := "n = a / b / c\nSECRET = 1"
	if k := kindOfSubstring(t, LangRuby, src, `SECRET = 1`); k != KindCode {
		t.Errorf("code after a division expression should be code, got %v", k)
	}
}
