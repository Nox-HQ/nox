package lexctx

import "testing"

// TestShellLangFromPath pins extension → LangShell mapping (case-insensitive).
func TestShellLangFromPath(t *testing.T) {
	for _, p := range []string{"deploy.sh", "scripts/build.BASH", "x.bash"} {
		if got := LangFromPath(p); got != LangShell {
			t.Errorf("LangFromPath(%q) = %v, want LangShell", p, got)
		}
	}
}

// TestShellLangString pins the stable lowercase label used in metadata/catalog.
func TestShellLangString(t *testing.T) {
	if got := LangShell.String(); got != "shell" {
		t.Errorf("LangShell.String() = %q, want %q", got, "shell")
	}
}

// TestScanShell exercises the headline shell lexical roles with one needle per
// role, mirroring TestScanRuby / TestScanGo.
func TestScanShell(t *testing.T) {
	src := "API_KEY=s3cr3t\n" +
		"# line comment s3cr3t\n" +
		"single='plain s3cr3t'\n" +
		"double=\"interp s3cr3t\"\n" +
		"ansic=$'ansi\\ts3cr3t'\n" +
		"cmd=`echo s3cr3t`\n" +
		"sub=$(echo s3cr3t)\n"
	cases := []struct {
		needle string
		want   Kind
	}{
		{`API_KEY=s3cr3t`, KindCode},
		{`line comment s3cr3t`, KindComment},
		{`'plain s3cr3t'`, KindString},
		{`"interp s3cr3t"`, KindString},
		{`$'ansi\ts3cr3t'`, KindString},
		// A backtick command substitution is a command LINE, so its body is code
		// (like $(...)); the taint layer needs the interpolated words visible.
		{"echo s3cr3t", KindCode},
	}
	for _, c := range cases {
		if k := kindOfSubstring(t, LangShell, src, c.needle); k != c.want {
			t.Errorf("needle %q: got %v, want %v", c.needle, k, c.want)
		}
	}
}

// TestShellLineComment: a `#` runs to end of line; the following line is code.
func TestShellLineComment(t *testing.T) {
	src := "x=1 # comment SECRET here\ny=2\n"
	if k := kindOfSubstring(t, LangShell, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `y=2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestShellHashInParamExpansionNotComment: a `#` inside ${#var} (string length)
// or $# (positional count) is NOT a comment — it lives in code.
func TestShellHashInParamExpansionNotComment(t *testing.T) {
	src := "len=${#name}\ncount=$#\nafter=ok\n"
	if k := kindOfSubstring(t, LangShell, src, `${#name}`); k != KindCode {
		t.Errorf("${#name} must be code, not comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `after=ok`); k != KindCode {
		t.Errorf("code after ${#..} should be code, got %v", k)
	}
	// $# followed by nothing on the line: the # is part of the expansion, so the
	// rest of that line is still code.
	if k := kindOfSubstring(t, LangShell, src, `count=`); k != KindCode {
		t.Errorf("count= assignment should be code, got %v", k)
	}
}

// TestShellSingleVsDouble: single quotes are literal (no interpolation); double
// quotes interpolate — but for lexctx purposes both bodies are string. The key
// distinction the test pins is that a `#` inside a quoted string is NOT a
// comment.
func TestShellSingleQuoteHashNotComment(t *testing.T) {
	src := "msg='not # a comment'\ntail=2\n"
	if k := kindOfSubstring(t, LangShell, src, `not # a comment`); k != KindString {
		t.Errorf("`#` inside single quotes should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `tail=2`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestShellDoubleQuoteHashNotComment: a `#` inside a double-quoted string is not
// a comment either.
func TestShellDoubleQuoteHashNotComment(t *testing.T) {
	src := "msg=\"issue #42 SECRET\"\ntail=2\n"
	if k := kindOfSubstring(t, LangShell, src, `issue #42 SECRET`); k != KindString {
		t.Errorf("`#` inside double quotes should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `tail=2`); k != KindCode {
		t.Errorf("code after the string should be code, got %v", k)
	}
}

// TestShellDollarInterpIsCode: a `$var` / `$(...)` inside a double-quoted string
// is CODE (a tainted value spliced in lives in a real expression), while the
// surrounding literal text is string.
func TestShellDollarInterpIsCode(t *testing.T) {
	src := "greet=\"hello $name done\"\n"
	if k := kindOfSubstring(t, LangShell, src, `hello `); k != KindString {
		t.Errorf("literal text in double quotes should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `$name`); k != KindCode {
		t.Errorf("$name interpolation should be code, got %v", k)
	}
}

// TestShellCommandSubInDoubleQuote: `$(...)` command substitution inside a
// double-quoted string is code.
func TestShellCommandSubInDoubleQuote(t *testing.T) {
	src := "out=\"result $(id -u) x\"\n"
	if k := kindOfSubstring(t, LangShell, src, `$(id -u)`); k != KindCode {
		t.Errorf("$(...) command substitution should be code, got %v", k)
	}
}

// TestShellAnsiCString: `$'...'` ANSI-C strings honor backslash escapes and are
// classified as string (no interpolation).
func TestShellAnsiCString(t *testing.T) {
	src := "s=$'line1\\nSECRET\\t'\ntail=2\n"
	if k := kindOfSubstring(t, LangShell, src, `line1\nSECRET\t`); k != KindString {
		t.Errorf("$'...' body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `tail=2`); k != KindCode {
		t.Errorf("code after $'...' should be code, got %v", k)
	}
}

// TestShellHeredoc: an unquoted heredoc body is string; the terminator returns
// to code. Covers <<EOF, <<'EOF' (no interp), and <<-EOF (indented terminator).
func TestShellHeredoc(t *testing.T) {
	src := "cat <<EOF\nblob SECRET line\nmore SECRET\nEOF\nafter=2\n"
	if k := kindOfSubstring(t, LangShell, src, `blob SECRET line`); k != KindString {
		t.Errorf("heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `after=2`); k != KindCode {
		t.Errorf("code after heredoc should be code, got %v", k)
	}
}

// TestShellQuotedHeredoc: a `<<'EOF'` heredoc body is string (no interpolation).
func TestShellQuotedHeredoc(t *testing.T) {
	src := "cat <<'EOF'\ntext $notinterp SECRET\nEOF\ndone=1\n"
	if k := kindOfSubstring(t, LangShell, src, `text $notinterp SECRET`); k != KindString {
		t.Errorf("quoted heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `done=1`); k != KindCode {
		t.Errorf("code after quoted heredoc should be code, got %v", k)
	}
}

// TestShellDashHeredoc: a `<<-EOF` heredoc allows a tab-indented terminator.
func TestShellDashHeredoc(t *testing.T) {
	src := "cat <<-END\n\tbody SECRET\n\tEND\nx=1\n"
	if k := kindOfSubstring(t, LangShell, src, `body SECRET`); k != KindString {
		t.Errorf("dash-heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangShell, src, `x=1`); k != KindCode {
		t.Errorf("code after dash-heredoc should be code, got %v", k)
	}
}

// TestShellDataBlobHeredoc: a long heredoc body is a data blob (string) — the
// SuppressNonCode path treats it as noise, so a secret-shaped run inside it is
// dropped, exactly as for other languages' long literals.
func TestShellDataBlobHeredoc(t *testing.T) {
	blob := "cat <<EOF\n"
	for i := 0; i < 6; i++ {
		blob += "AKIAIOSFODNN7EXAMPLEDATABLOBLONGLINE1234567890\n"
	}
	blob += "EOF\n"
	// A match inside the blob body should be suppressible as a data blob string.
	off := indexOf(blob, "AKIAIOSFODNN7EXAMPLE")
	if off < 0 {
		t.Fatal("test blob missing needle")
	}
	if !InDataBlob(LangShell, []byte(blob), off, off+len("AKIAIOSFODNN7EXAMPLE")) {
		t.Errorf("long heredoc body should be treated as a data blob")
	}
}
