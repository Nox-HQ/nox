package lexctx

import "testing"

// TestScanPerl exercises the headline Perl lexical roles the same way
// TestScanRuby / TestScanGo do: one fixture, one needle per role. It pins the
// code/string/comment classification the SAST analyzers rely on for Perl.
func TestScanPerl(t *testing.T) {
	src := "my $api_key = \"s3cr3t\";\n" +
		"# line comment s3cr3t\n" +
		"my $single = 'plain s3cr3t';\n" +
		"my $cmd = `echo s3cr3t`;\n" +
		"my $words = qw(a s3cr3t c);\n"
	if k := kindOfSubstring(t, LangPerl, src, `api_key`); k != KindCode {
		t.Errorf("api_key should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `'plain s3cr3t'`); k != KindString {
		t.Errorf("single-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, "`echo s3cr3t`"); k != KindString {
		t.Errorf("backtick command string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `a s3cr3t c`); k != KindString {
		t.Errorf("qw() quote-like body should be string, got %v", k)
	}
}

func TestPerlLangFromPath(t *testing.T) {
	for _, ext := range []string{"lib/App.pm", "bin/run.pl", "cgi-bin/index.cgi", "t/basic.t"} {
		if got := LangFromPath(ext); got != LangPerl {
			t.Errorf("LangFromPath(%q) = %v, want %v", ext, got, LangPerl)
		}
	}
	if got := LangFromPath("SCRIPT.PL"); got != LangPerl {
		t.Errorf("LangFromPath is not case-insensitive for .pl, got %v", got)
	}
}

func TestPerlLangString(t *testing.T) {
	if got := LangPerl.String(); got != "perl" {
		t.Errorf("LangPerl.String() = %q, want %q", got, "perl")
	}
}

// TestPerlLineComment: a `#` runs to end of line; the following line is code.
func TestPerlLineComment(t *testing.T) {
	src := "my $x = 1; # comment SECRET here\nmy $y = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestPerlArrayLenNotComment: `$#array` (last-index sigil) must NOT open a
// comment — the `#` there is part of the special variable, not a comment.
func TestPerlArrayLenNotComment(t *testing.T) {
	src := "my $last = $#items;\nmy $SECRET = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `$SECRET = 2`); k != KindCode {
		t.Errorf("code after $#array must be code (the # is not a comment), got %v", k)
	}
}

// TestPerlPodBlock: a `=pod` / `=head1` ... `=cut` block is a comment spanning
// many lines; code after `=cut` is code. Markers must start at column 0.
func TestPerlPodBlock(t *testing.T) {
	src := "my $before = 1;\n=head1 NAME\nblock SECRET line\nmore SECRET\n=cut\nmy $after = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `block SECRET line`); k != KindComment {
		t.Errorf("POD block body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `=head1 NAME`); k != KindComment {
		t.Errorf("POD directive line should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$after = 2`); k != KindCode {
		t.Errorf("code after =cut should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$before = 1`); k != KindCode {
		t.Errorf("code before the POD block should be code, got %v", k)
	}
}

// TestPerlPodNotAtColumnZero: an `=head1` indented off column 0 must NOT open a
// POD block (in real Perl a `=` directive must be at column 0).
func TestPerlPodNotAtColumnZero(t *testing.T) {
	src := "my $x = 1;\n  =head1 not pod\nmy $SECRET = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `$SECRET = 2`); k != KindCode {
		t.Errorf("code after an indented (non-)=head1 should be code, got %v", k)
	}
}

// TestPerlSingleQuoteNoInterp: single-quoted strings do not interpolate; a
// `$var` inside them is literal string, not code.
func TestPerlSingleQuoteNoInterp(t *testing.T) {
	src := "my $q = 'no $interp here';\nmy $SECRET = 1;"
	if k := kindOfSubstring(t, LangPerl, src, `$interp`); k != KindString {
		t.Errorf("$var inside single quotes must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$SECRET = 1`); k != KindCode {
		t.Errorf("code after a single-quoted string should be code, got %v", k)
	}
}

// TestPerlEscapedQuote: a `\"` must not close a double-quoted string, so the
// trailing code stays code.
func TestPerlEscapedQuote(t *testing.T) {
	src := `my $s = "a\"b"; my $SECRET = 1;`
	if k := kindOfSubstring(t, LangPerl, src, `$SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `a\"b`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestPerlBacktickCommand: a backtick command string is string-kind; code after
// it is code.
func TestPerlBacktickCommand(t *testing.T) {
	src := "my $out = `whoami SECRET`;\nmy $after = 1;"
	if k := kindOfSubstring(t, LangPerl, src, "whoami SECRET"); k != KindString {
		t.Errorf("backtick command body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$after = 1`); k != KindCode {
		t.Errorf("code after a backtick command should be code, got %v", k)
	}
}

// TestPerlQuoteLikes: the q()/qq()/qw()/qx() quote-like operators are
// string-kind, and code after them is code.
func TestPerlQuoteLikes(t *testing.T) {
	src := "my $a = q(single SECRET);\n" +
		"my $b = qq(double SECRET);\n" +
		"my $c = qx(cmd SECRET);\n" +
		"my $after = 1;"
	if k := kindOfSubstring(t, LangPerl, src, `single SECRET`); k != KindString {
		t.Errorf("q() body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `double SECRET`); k != KindString {
		t.Errorf("qq() body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `cmd SECRET`); k != KindString {
		t.Errorf("qx() body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$after = 1`); k != KindCode {
		t.Errorf("code after quote-likes should be code, got %v", k)
	}
}

// TestPerlQuoteLikeBracketDelims: a bracket-delimited quote-like nests its
// matching delimiter so an inner `)` does not close it early.
func TestPerlQuoteLikeBrackets(t *testing.T) {
	src := "my $x = qq{a {nested} SECRET};\nmy $after = 1;"
	if k := kindOfSubstring(t, LangPerl, src, `nested} SECRET`); k != KindString {
		t.Errorf("nested-brace quote-like body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$after = 1`); k != KindCode {
		t.Errorf("code after a nested quote-like should be code, got %v", k)
	}
}

// TestPerlHeredocDouble: a `<<"EOF"` heredoc body is a string spanning lines;
// code after the terminator is code.
func TestPerlHeredocDouble(t *testing.T) {
	src := "my $sql = <<\"EOF\";\nSELECT SECRET FROM users\nWHERE 1=1\nEOF\nmy $after = 1;"
	if k := kindOfSubstring(t, LangPerl, src, `SELECT SECRET FROM users`); k != KindString {
		t.Errorf("heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$after = 1`); k != KindCode {
		t.Errorf("code after a heredoc terminator should be code, got %v", k)
	}
}

// TestPerlHeredocSingle: a `<<'EOF'` (non-interpolating) heredoc body is string.
func TestPerlHeredocSingle(t *testing.T) {
	src := "my $t = <<'END';\nbody BLOB $notvar line\nEND\nmy $next = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `body BLOB`); k != KindString {
		t.Errorf("<<'END' heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$next = 2`); k != KindCode {
		t.Errorf("code after a single-quoted heredoc terminator should be code, got %v", k)
	}
}

// TestPerlHeredocIndented: a `<<~EOF` heredoc allows an indented terminator.
func TestPerlHeredocIndented(t *testing.T) {
	src := "my $t = <<~EOF;\n    indented BLOB line\n    EOF\nmy $next = 2;"
	if k := kindOfSubstring(t, LangPerl, src, `indented BLOB line`); k != KindString {
		t.Errorf("<<~EOF heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$next = 2`); k != KindCode {
		t.Errorf("code after an indented heredoc terminator should be code, got %v", k)
	}
}

// TestPerlDataBlobInHeredocSuppressed proves the payoff: a long base64/data-URI
// payload inside a Perl heredoc is a blob (suppressed), while a short secret in
// an ordinary string is NOT (kept).
func TestPerlDataBlobInHeredocSuppressed(t *testing.T) {
	longBlob := "my $icon = <<'DATA';\ndata:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\nDATA\n"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangPerl, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI heredoc blob must be reported as a data blob")
	}

	shortSecret := []byte(`my $api_key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangPerl, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Perl string must NOT be a data blob")
	}
}

// TestPerlSuppressNonCodePolicy mirrors the Ruby/Go policy test: a comment match
// and a data-blob-string match are dropped by SuppressNonCode, while a short
// ordinary-string secret is kept.
func TestPerlSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("my $x = 1; # AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangPerl, comment, k, k+32) {
		t.Error("a token inside a Perl comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`my $key = "AKIA1234567890ABCDEF1234567890AB";`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangPerl, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Perl string literal must NOT be suppressed")
	}
}

// TestPerlInterpolationInDoubleQuote: a `$var` interpolation inside a
// double-quoted string is emitted as CODE (a tainted value spliced into
// "id=$id" lives in a real expression), while the surrounding literal is string.
func TestPerlInterpolationInDoubleQuote(t *testing.T) {
	src := "my $q = \"SELECT $user_input FROM t\";\nmy $SECRET = 1;"
	if k := kindOfSubstring(t, LangPerl, src, `user_input`); k != KindCode {
		t.Errorf("$var interpolation field should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `SELECT `); k != KindString {
		t.Errorf("literal part of the string should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPerl, src, `$SECRET = 1`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}
