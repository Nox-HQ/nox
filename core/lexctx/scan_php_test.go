package lexctx

import "testing"

// TestScanPHP exercises the headline PHP lexical roles the same way the Python /
// Go scanner tests do: one fixture, one needle per role. It pins the code /
// string / comment classification the secrets and taint analyzers rely on when
// gating findings in PHP source.
func TestScanPHP(t *testing.T) {
	src := "<?php\n" +
		"$apiKey = 's3cr3t';\n" +
		"// line comment s3cr3t\n" +
		"# hash comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"$dq = \"interp s3cr3t\";\n" +
		"?>\n"
	if k := kindOfSubstring(t, LangPHP, src, `$apiKey`); k != KindCode {
		t.Errorf("$apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `'s3cr3t'`); k != KindString {
		t.Errorf("single-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("// line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `hash comment s3cr3t`); k != KindComment {
		t.Errorf("# hash comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("/* block comment */ should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `interp s3cr3t`); k != KindString {
		t.Errorf("double-quoted string body should be string, got %v", k)
	}
}

func TestPHPLangFromPath(t *testing.T) {
	if got := LangFromPath("src/index.php"); got != LangPHP {
		t.Errorf("LangFromPath(.php) = %v, want %v", got, LangPHP)
	}
	if got := LangFromPath("tpl/page.phtml"); got != LangPHP {
		t.Errorf("LangFromPath(.phtml) = %v, want %v", got, LangPHP)
	}
	if got := LangFromPath("UPPER.PHP"); got != LangPHP {
		t.Errorf("LangFromPath is not case-insensitive for .php, got %v", got)
	}
}

func TestPHPLangString(t *testing.T) {
	if got := LangPHP.String(); got != "php" {
		t.Errorf("LangPHP.String() = %q, want %q", got, "php")
	}
}

// TestPHPHTMLOutsideTagsIsNonCode pins the crucial PHP boundary rule: text
// OUTSIDE <?php ... ?> is literal HTML output, not code. It must classify as a
// non-code (string) region so the taint recognizer ignores it, while code inside
// the tags stays code.
func TestPHPHTMLOutsideTagsIsNonCode(t *testing.T) {
	src := "<html>SECRET_html</html>\n<?php $x = 1; // SECRET_code\n?>\ntrailing SECRET_html2"
	if k := kindOfSubstring(t, LangPHP, src, `SECRET_html`); k != KindString {
		t.Errorf("HTML before <?php should be non-code (string), got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$x = 1`); k != KindCode {
		t.Errorf("code inside <?php should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `SECRET_html2`); k != KindString {
		t.Errorf("HTML after ?> should be non-code (string), got %v", k)
	}
}

// TestPHPShortEchoTag: <?= expr ?> is a code island too (echo shorthand).
func TestPHPShortEchoTag(t *testing.T) {
	src := "before <?= $userVar . 'x' ?> after"
	if k := kindOfSubstring(t, LangPHP, src, `$userVar`); k != KindCode {
		t.Errorf("<?= island should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `before `); k != KindString {
		t.Errorf("HTML before <?= should be non-code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, ` after`); k != KindString {
		t.Errorf("HTML after ?> should be non-code, got %v", k)
	}
}

// TestPHPSingleQuoteNoInterp: a single-quoted string does not interpolate; a `$`
// inside it stays string, and a following code token stays code.
func TestPHPSingleQuoteNoInterp(t *testing.T) {
	src := "<?php $s = 'no $interp here'; $SECRET = 1;"
	if k := kindOfSubstring(t, LangPHP, src, `no $interp here`); k != KindString {
		t.Errorf("single-quoted body (with a literal $) should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET`); k != KindCode {
		t.Errorf("code after a single-quoted string should be code, got %v", k)
	}
}

// TestPHPSingleQuoteEscapedQuote: `\'` must not close a single-quoted string.
func TestPHPSingleQuoteEscapedQuote(t *testing.T) {
	src := "<?php $s = 'a\\'b'; $SECRET = 1;"
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
}

// TestPHPDoubleQuoteEscapedQuote: `\"` must not close a double-quoted string.
func TestPHPDoubleQuoteEscapedQuote(t *testing.T) {
	src := "<?php $s = \"a\\\"b\"; $SECRET = 1;"
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote double string should be code, got %v", k)
	}
}

// TestPHPDoubleSlashInsideStringIsNotComment: a URL `//` inside a string must
// not open a comment.
func TestPHPDoubleSlashInsideStringIsNotComment(t *testing.T) {
	src := "<?php $u = \"https://example.com/x\"; $SECRET = 1;"
	if k := kindOfSubstring(t, LangPHP, src, `//example`); k != KindString {
		t.Errorf("`//` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestPHPHeredocInterpolates: a heredoc <<<EOT ... EOT spans lines and is string;
// code after the closing marker stays code.
func TestPHPHeredocInterpolates(t *testing.T) {
	src := "<?php\n$q = <<<EOT\nSELECT SECRET_body\nfrom t\nEOT;\n$SECRET_after = 1;\n"
	if k := kindOfSubstring(t, LangPHP, src, `SECRET_body`); k != KindString {
		t.Errorf("heredoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET_after`); k != KindCode {
		t.Errorf("code after a heredoc close should be code, got %v", k)
	}
}

// TestPHPNowdocNoInterp: a nowdoc <<<'EOT' ... EOT is string (no interpolation);
// the `$` inside stays string and code after the marker stays code.
func TestPHPNowdocNoInterp(t *testing.T) {
	src := "<?php\n$q = <<<'EOT'\nliteral $notvar SECRET_now\nEOT;\n$SECRET_after = 1;\n"
	if k := kindOfSubstring(t, LangPHP, src, `SECRET_now`); k != KindString {
		t.Errorf("nowdoc body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET_after`); k != KindCode {
		t.Errorf("code after a nowdoc close should be code, got %v", k)
	}
}

// TestPHPHashCommentToEOL: a `#` comment runs to end of line; the next line is
// code.
func TestPHPHashCommentToEOL(t *testing.T) {
	src := "<?php $x = 1; # comment SECRET_c\n$SECRET_next = 2;"
	if k := kindOfSubstring(t, LangPHP, src, `comment SECRET_c`); k != KindComment {
		t.Errorf("# comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPHP, src, `$SECRET_next`); k != KindCode {
		t.Errorf("code after a # comment should be code, got %v", k)
	}
}

// TestPHPDataBlobInString proves the payoff: a long base64/data-URI payload in a
// PHP string is a blob (suppressed), while a short secret in an ordinary string
// is NOT (kept).
func TestPHPDataBlobInString(t *testing.T) {
	longBlob := "<?php $icon = 'data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==';"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangPHP, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI PHP string must be reported as a data blob")
	}

	shortSecret := []byte("<?php $apiKey = 'AKIA1234567890ABCDEF1234567890AB';")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangPHP, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary PHP string must NOT be a data blob")
	}
}

// TestPHPSuppressNonCodePolicy: a comment match and a data-blob-string match are
// dropped by SuppressNonCode, while a short ordinary-string secret is kept.
func TestPHPSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("<?php $x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangPHP, comment, k, k+32) {
		t.Error("a token inside a PHP comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte("<?php $key = 'AKIA1234567890ABCDEF1234567890AB';")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangPHP, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a PHP string literal must NOT be suppressed")
	}
}

// TestPHPRegionsCover ensures the scanner emits a gap-free covering partition.
func TestPHPRegionsCover(t *testing.T) {
	src := "html <?php $x = 'a'; // c\n?> tail"
	regions := Classify(LangPHP, []byte(src))
	regionsCover(t, regions, len(src))
}
