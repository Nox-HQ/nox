package lexctx

import "testing"

// TestScanPowerShell exercises the headline PowerShell lexical roles the same way
// TestScanGo / TestScanPython do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and taint analyzers rely on when
// gating findings in PowerShell source.
func TestScanPowerShell(t *testing.T) {
	src := "$apiKey = 's3cr3t'\n" +
		"# line comment s3cr3t\n" +
		"<# block s3cr3t comment #>\n" +
		"$msg = \"hello $name s3cr3t\"\n" +
		"Write-Host 'plain'\n"
	if k := kindOfSubstring(t, LangPowerShell, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `'s3cr3t'`); k != KindString {
		t.Errorf("single-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `hello `); k != KindString {
		t.Errorf("double-quoted string body should be string, got %v", k)
	}
}

func TestPowerShellLangFromPath(t *testing.T) {
	for _, p := range []string{"deploy.ps1", "Module.psm1", "Manifest.psd1"} {
		if got := LangFromPath(p); got != LangPowerShell {
			t.Errorf("LangFromPath(%q) = %v, want %v", p, got, LangPowerShell)
		}
	}
	if got := LangFromPath("UPPER.PS1"); got != LangPowerShell {
		t.Errorf("LangFromPath is not case-insensitive for .ps1, got %v", got)
	}
}

func TestPowerShellLangString(t *testing.T) {
	if got := LangPowerShell.String(); got != "powershell" {
		t.Errorf("LangPowerShell.String() = %q, want %q", got, "powershell")
	}
}

// TestPowerShellBlockCommentSpansLines: `<# ... #>` crosses newlines and does NOT
// nest, so the FIRST `#>` closes it and the rest is code.
func TestPowerShellBlockCommentSpansLines(t *testing.T) {
	src := "before\n<# multi\n line SECRET\n comment #>\n$after = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line block comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `after`); k != KindCode {
		t.Errorf("code after a block comment should be code, got %v", k)
	}
}

// TestPowerShellBlockCommentNotNested pins the non-nesting rule: the first `#>`
// ends the comment even though an inner `<#` appeared, so the trailing code is
// code.
func TestPowerShellBlockCommentNotNested(t *testing.T) {
	src := "<# outer <# inner #> $SECRET = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `inner`); k != KindComment {
		t.Errorf("bytes before the first close should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `SECRET`); k != KindCode {
		t.Errorf("bytes after the first `#>` should be code (no nesting), got %v", k)
	}
}

// TestPowerShellSingleQuoteNoInterp: a single-quoted string does NOT interpolate,
// so a `$var` inside stays string, and a doubled quote `”` is a literal quote
// that does not close the string.
func TestPowerShellSingleQuoteNoInterp(t *testing.T) {
	src := "$s = 'it''s a $var literal' ; $SECRET = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `$var literal`); k != KindString {
		t.Errorf("`$var` inside a single-quoted string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `SECRET`); k != KindCode {
		t.Errorf("code after a doubled-quote single string should be code, got %v", k)
	}
}

// TestPowerShellDoubleQuoteSubexpr: a `$( ... )` subexpression inside a
// double-quoted string is CODE (a real expression), while the surrounding literal
// bytes stay string.
func TestPowerShellDoubleQuoteSubexpr(t *testing.T) {
	src := "$q = \"id=$($request.query)-end\"\n$SECRET = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `id=`); k != KindString {
		t.Errorf("literal prefix of an interpolated string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `request.query`); k != KindCode {
		t.Errorf("`$( ... )` subexpression must be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `-end`); k != KindString {
		t.Errorf("literal suffix after a subexpression should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `SECRET`); k != KindCode {
		t.Errorf("code after the interpolated string should be code, got %v", k)
	}
}

// TestPowerShellDoubleQuoteBacktickEscape: a backtick-escaped quote does NOT close
// the string, so trailing code stays code.
func TestPowerShellDoubleQuoteBacktickEscape(t *testing.T) {
	src := "$s = \"a`\"b\" ; $SECRET = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `SECRET`); k != KindCode {
		t.Errorf("code after a backtick-escaped-quote string should be code, got %v", k)
	}
}

// TestPowerShellHashInStringNotComment: a `#` inside a string must not begin a
// comment.
func TestPowerShellHashInStringNotComment(t *testing.T) {
	src := "$u = \"http://h/#frag SECRET\" ; $x = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `#frag SECRET`); k != KindString {
		t.Errorf("`#` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `$x = 1`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestPowerShellHereStringInterp: an interpolating here-string @"..."@ body spans
// lines and is string; a `$( ... )` field in it is code; a `#` in the body is not
// a comment; and code after the terminator is code.
func TestPowerShellHereStringInterp(t *testing.T) {
	src := "$doc = @\"\nline1 SECRET # not a comment\ntotal=$($sum)\n\"@\n$after = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `line1 SECRET # not a comment`); k != KindString {
		t.Errorf("interpolating here-string body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `sum`); k != KindCode {
		t.Errorf("`$( ... )` field in a here-string must be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `after`); k != KindCode {
		t.Errorf("code after a here-string terminator should be code, got %v", k)
	}
}

// TestPowerShellHereStringLiteral: a literal here-string @'...'@ does NOT
// interpolate — a `$( ... )` inside stays string — and code after the terminator
// is code.
func TestPowerShellHereStringLiteral(t *testing.T) {
	src := "$blob = @'\nAKIA1234 $(not-code) here\n'@\n$after = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `$(not-code) here`); k != KindString {
		t.Errorf("literal here-string body (incl `$(...)`) must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `after`); k != KindCode {
		t.Errorf("code after a literal here-string terminator should be code, got %v", k)
	}
}

// TestPowerShellHereStringTerminatorColumnZero: the terminator `"@` only closes at
// column 0. An indented `"@` inside the body does NOT close the here-string.
func TestPowerShellHereStringTerminatorColumnZero(t *testing.T) {
	src := "$doc = @\"\nbody line\n    \"@ indented not a terminator\nreal SECRET\n\"@\n$after = 1"
	if k := kindOfSubstring(t, LangPowerShell, src, `indented not a terminator`); k != KindString {
		t.Errorf("an indented `\"@` must NOT terminate the here-string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `real SECRET`); k != KindString {
		t.Errorf("body after the fake terminator should still be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPowerShell, src, `after`); k != KindCode {
		t.Errorf("code after the real column-0 terminator should be code, got %v", k)
	}
}

// TestPowerShellDataBlobHereStringSuppressed proves the payoff: a long base64/
// data-URI payload inside a here-string is a blob (suppressed), while a short
// secret in an ordinary single-quoted string is NOT (kept).
func TestPowerShellDataBlobHereStringSuppressed(t *testing.T) {
	longBlob := "$icon = @'\ndata:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\n'@\n"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangPowerShell, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI here-string blob must be reported as a data blob")
	}

	shortSecret := []byte("$apiKey = 'AKIA1234567890ABCDEF1234567890AB'")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangPowerShell, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary PowerShell string must NOT be a data blob")
	}
}

// TestPowerShellSuppressNonCodePolicy mirrors the Go/Python policy test: a comment
// match and a data-blob-string match are dropped by SuppressNonCode, while a short
// ordinary-string secret is kept.
func TestPowerShellSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("$x = 1 # AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangPowerShell, comment, k, k+32) {
		t.Error("a token inside a PowerShell comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte("$key = 'AKIA1234567890ABCDEF1234567890AB'")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangPowerShell, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a PowerShell string literal must NOT be suppressed")
	}
}
