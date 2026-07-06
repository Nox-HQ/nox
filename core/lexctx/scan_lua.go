package lexctx

// scanLua walks Lua source and classifies each byte as code, string, or comment.
// It recognizes:
//
//   - `--` line comments (to end of line) — unless the `--` is immediately
//     followed by a long-bracket opener `[[` / `[==[`, in which case it is a
//     long-bracket BLOCK comment that spans lines until the matching `]==]`.
//   - single- and double-quoted string literals with backslash escapes; these do
//     NOT cross a newline (Lua requires an explicit `\` continuation), so a
//     runaway quote never swallows the following line's code.
//   - long strings `[[ ... ]]` / `[==[ ... ]==]` — multi-line, NO escape
//     processing, closed only by a `]` run with the SAME number of `=` signs as
//     the opener. These are the workhorse for embedding blobs and templates.
//
// Lua has no character literal (a `'x'` is a one-byte string) and long brackets
// come in "levels": `[` `=`×N `[` opens level N and only `]` `=`×N `]` closes it,
// so an inner `]]` inside a `[==[ … ]==]` does not terminate it. That leveling is
// the crux of correctly classifying Lua data blobs.
func scanLua(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	for i < n {
		c := content[i]
		switch {
		case c == '-' && i+1 < n && content[i+1] == '-':
			// A comment. It may be a long-bracket block comment if `--` is followed
			// immediately by a long-bracket opener; otherwise a line comment.
			start := i
			if lvl, bodyStart, ok := luaLongBracketOpen(content, i+2); ok {
				end := luaLongBracketClose(content, bodyStart, lvl)
				b.emit(start, end, KindComment)
				i = end
				continue
			}
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '\'' || c == '"':
			i = scanLuaQuoted(content, i, &b)
		case c == '[':
			// A long string opener `[[` / `[==[`, or an ordinary `[` index/table.
			if lvl, bodyStart, ok := luaLongBracketOpen(content, i); ok {
				start := i
				end := luaLongBracketClose(content, bodyStart, lvl)
				b.emit(start, end, KindString)
				i = end
				continue
			}
			b.emit(i, i+1, KindCode)
			i++
		default:
			b.emit(i, i+1, KindCode)
			i++
		}
	}
	return b.finish(n)
}

// luaLongBracketOpen reports whether content[i:] begins a long-bracket opener
// `[` `=`×level `[`. It returns the level (number of `=` signs), the index of the
// first body byte just past the second `[`, and ok=true. A single `[` not
// followed by `=`* `[` (an ordinary index or table constructor) yields ok=false.
func luaLongBracketOpen(content []byte, i int) (level, bodyStart int, ok bool) {
	n := len(content)
	if i >= n || content[i] != '[' {
		return 0, 0, false
	}
	j := i + 1
	for j < n && content[j] == '=' {
		j++
	}
	if j < n && content[j] == '[' {
		return j - (i + 1), j + 1, true
	}
	return 0, 0, false
}

// luaLongBracketClose returns the offset just past the closing long bracket
// `]` `=`×level `]` that matches an opener of the given level, scanning from
// bodyStart. An unterminated long bracket runs to end of input (its bytes stay
// inside the string/comment region, so a runaway blob never leaks as code).
func luaLongBracketClose(content []byte, bodyStart, level int) int {
	n := len(content)
	i := bodyStart
	for i < n {
		if content[i] != ']' {
			i++
			continue
		}
		j := i + 1
		eq := 0
		for j < n && content[j] == '=' {
			eq++
			j++
		}
		if eq == level && j < n && content[j] == ']' {
			return j + 1
		}
		i++
	}
	return n
}

// scanLuaQuoted classifies a single- or double-quoted Lua string starting at the
// opening quote content[start]. Backslash escapes are honored; the string ends at
// the matching unescaped quote or, defensively, at a newline (a quoted Lua string
// may not span a raw newline). Returns the offset just past the literal.
func scanLuaQuoted(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	q := content[start]
	i := start + 1
	for i < n {
		c := content[i]
		switch c {
		case '\\':
			i += 2 // escaped byte stays inside the string
			continue
		case q:
			b.emit(start, i+1, KindString)
			return i + 1
		case '\n':
			b.emit(start, i, KindString)
			return i
		}
		i++
	}
	b.emit(start, n, KindString)
	return n
}
