package lexctx

import "testing"

// TestScanLua exercises the headline Lua lexical roles the same way TestScanGo /
// TestScanPython do: one fixture, one needle per role. It pins the
// code/string/comment classification the secrets and AI analyzers rely on when
// gating findings in Lua source.
func TestScanLua(t *testing.T) {
	src := "local apiKey = \"s3cr3t\"\n" +
		"-- line comment s3cr3t\n" +
		"--[[ block s3cr3t comment ]]\n" +
		"local raw = [[ template s3cr3t line ]]\n" +
		"local sq = 's'\n"
	if k := kindOfSubstring(t, LangLua, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted string literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("long-bracket block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `[[ template s3cr3t line ]]`); k != KindString {
		t.Errorf("long string should be string, got %v", k)
	}
}

func TestLuaLangFromPath(t *testing.T) {
	if got := LangFromPath("src/init.lua"); got != LangLua {
		t.Errorf("LangFromPath(.lua) = %v, want %v", got, LangLua)
	}
	if got := LangFromPath("UPPER.LUA"); got != LangLua {
		t.Errorf("LangFromPath is not case-insensitive for .lua, got %v", got)
	}
}

func TestLuaLangString(t *testing.T) {
	if got := LangLua.String(); got != "lua" {
		t.Errorf("LangLua.String() = %q, want %q", got, "lua")
	}
}

// TestLuaLineComment: a `--` runs to end of line; the following line is code.
func TestLuaLineComment(t *testing.T) {
	src := "x = 1 -- comment SECRET here\ny = 2"
	if k := kindOfSubstring(t, LangLua, src, `comment SECRET here`); k != KindComment {
		t.Errorf("line-comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `y = 2`); k != KindCode {
		t.Errorf("code after a line comment should be code, got %v", k)
	}
}

// TestLuaLongBracketCommentSpansLines: `--[[ ... ]]` crosses newlines and closes
// at the first matching `]]`; the rest is code.
func TestLuaLongBracketCommentSpansLines(t *testing.T) {
	src := "before = 1\n--[[ multi\n line SECRET\n comment ]]\nafter = 2"
	if k := kindOfSubstring(t, LangLua, src, `line SECRET`); k != KindComment {
		t.Errorf("multi-line long-bracket comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `after = 2`); k != KindCode {
		t.Errorf("code after a long-bracket comment should be code, got %v", k)
	}
}

// TestLuaLongBracketCommentWithEqualsLevel pins the leveled long bracket: a
// `--[==[ ... ]==]` comment is only closed by a `]==]` with the SAME number of
// `=`; an inner `]]` or `]=]` does NOT close it.
func TestLuaLongBracketCommentWithEqualsLevel(t *testing.T) {
	src := "--[==[ outer ]] still SECRET ]=] still ]==]\nafter = 1"
	if k := kindOfSubstring(t, LangLua, src, `still SECRET`); k != KindComment {
		t.Errorf("bytes before the matching close level should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `after = 1`); k != KindCode {
		t.Errorf("code after the matching `]==]` should be code, got %v", k)
	}
}

// TestLuaLongString: a `[[ ... ]]` long string spans lines, processes NO escapes,
// and its `--` / quotes inside are not comments/strings. Trailing code is code.
func TestLuaLongString(t *testing.T) {
	src := "blob = [[ line1 -- not a comment\nline2 \"not a string\" SECRET ]]\nafter = 1"
	if k := kindOfSubstring(t, LangLua, src, `-- not a comment`); k != KindString {
		t.Errorf("`--` inside a long string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `not a string`); k != KindString {
		t.Errorf("`\"` inside a long string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `after = 1`); k != KindCode {
		t.Errorf("code after a long string should be code, got %v", k)
	}
}

// TestLuaLongStringLevel: `[==[ ... ]==]` is only closed by `]==]`; an inner `]]`
// does not close it.
func TestLuaLongStringLevel(t *testing.T) {
	src := "s = [==[ inner ]] still SECRET ]==] ; after = 1"
	if k := kindOfSubstring(t, LangLua, src, `still SECRET`); k != KindString {
		t.Errorf("bytes before the matching close level should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `after = 1`); k != KindCode {
		t.Errorf("code after the matching `]==]` should be code, got %v", k)
	}
}

// TestLuaSingleQuoteString: single-quoted strings carry backslash escapes; an
// escaped quote must not close it, so trailing code stays code.
func TestLuaSingleQuoteEscapedQuote(t *testing.T) {
	src := `s = 'a\'b' ; SECRET = 1`
	if k := kindOfSubstring(t, LangLua, src, `SECRET`); k != KindCode {
		t.Errorf("code after an escaped-quote string should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `'a\'b'`); k != KindString {
		t.Errorf("escaped-quote string body should be string, got %v", k)
	}
}

// TestLuaStringEndsAtNewline: a quoted string does not cross a newline (Lua
// requires an explicit `\` line continuation), so the next line stays code.
func TestLuaStringEndsAtNewline(t *testing.T) {
	src := "s = \"unterminated\nSECRET = 1"
	if k := kindOfSubstring(t, LangLua, src, `SECRET`); k != KindCode {
		t.Errorf("code after a newline-terminated string should be code, got %v", k)
	}
}

// TestLuaDoubleDashInsideStringIsNotComment: a `--` inside a quoted string must
// not begin a comment.
func TestLuaDoubleDashInsideStringIsNotComment(t *testing.T) {
	src := `url = "http://example.com/a--b" ; SECRET = 1`
	if k := kindOfSubstring(t, LangLua, src, `a--b`); k != KindString {
		t.Errorf("`--` inside a string must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `SECRET`); k != KindCode {
		t.Errorf("code after the URL string should be code, got %v", k)
	}
}

// TestLuaLineCommentNotLongBracket: `-- [[` with a space (or any non-`[`
// immediately after `--`) is a plain LINE comment, not a long-bracket comment, so
// it ends at the newline.
func TestLuaLineCommentNotLongBracket(t *testing.T) {
	src := "-- just a note [[ not opened\nafter = 1"
	if k := kindOfSubstring(t, LangLua, src, `not opened`); k != KindComment {
		t.Errorf("plain line comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `after = 1`); k != KindCode {
		t.Errorf("code after a plain line comment should be code, got %v", k)
	}
}

// TestLuaBracketIndexNotLongString: a single `[` for table indexing is not a long
// string; `t[i]` must stay code.
func TestLuaBracketIndexNotLongString(t *testing.T) {
	src := "v = t[idx] ; SECRET = 1"
	if k := kindOfSubstring(t, LangLua, src, `t[idx]`); k != KindCode {
		t.Errorf("a single-bracket index must stay code, got %v", k)
	}
	if k := kindOfSubstring(t, LangLua, src, `SECRET`); k != KindCode {
		t.Errorf("code after a table index should be code, got %v", k)
	}
}

// TestLuaDataBlobInLongStringSuppressed proves the payoff: a long base64/data-URI
// payload inside a Lua long string is a blob (suppressed), while a short secret in
// an ordinary quoted string is NOT (kept).
func TestLuaDataBlobInLongStringSuppressed(t *testing.T) {
	longBlob := "local icon = [[data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==]]"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangLua, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI long-string blob must be reported as a data blob")
	}

	shortSecret := []byte(`local apiKey = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangLua, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary Lua string must NOT be a data blob")
	}
}

// TestLuaSuppressNonCodePolicy mirrors the Go/Python policy test for Lua: a
// comment match and a data-blob-string match are dropped by SuppressNonCode,
// while a short ordinary-string secret is kept.
func TestLuaSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("x = 1 -- AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangLua, comment, k, k+32) {
		t.Error("a token inside a Lua comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte(`key = "AKIA1234567890ABCDEF1234567890AB"`)
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangLua, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in a Lua string literal must NOT be suppressed")
	}
}
