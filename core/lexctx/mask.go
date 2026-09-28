package lexctx

// MaskNonCode returns a copy of content in which every comment byte and every
// string body byte is a space, with newlines, byte offsets and string
// delimiters kept. A string keeps its prefix and opening quotes and its
// closing quotes, so `f"a{b}c"` becomes `f"  {b}  "` in Python (the
// interpolation is code) and `'secret'` becomes `'      '`.
//
// It is for detectors that read code as text -- matching names, brackets and
// calls -- and must not be fooled by the same text inside a comment or a
// literal. Offsets are unchanged, so a match in the mask is a match at the same
// offset and line in content.
func MaskNonCode(lang Lang, content []byte) []byte {
	out := make([]byte, len(content))
	copy(out, content)
	for _, r := range Classify(lang, content) {
		switch r.Kind {
		case KindCode:
			continue
		case KindString:
			// A string region that starts right after an interpolation's `}`
			// continues an f-string or template literal: it has no prefix.
			continuation := r.Start > 0 && content[r.Start-1] == '}'
			keepFrom, keepTo := stringDelimiters(content[r.Start:r.End], continuation)
			blank(out, r.Start+keepFrom, r.Start+keepTo)
		default:
			blank(out, r.Start, r.End)
		}
	}
	return out
}

// stringDelimiters returns the span of a string region's body: after a
// leading prefix (up to two letters) and its opening quotes, before the closing
// quotes. A continuation has neither prefix nor opening quote.
func stringDelimiters(s []byte, continuation bool) (from, to int) {
	i := 0
	for !continuation && i < len(s) && i < 2 && isLetter(s[i]) {
		i++
	}
	if !continuation && i < len(s) && isQuote(s[i]) {
		for i < len(s) && isQuote(s[i]) {
			i++
		}
	} else {
		i = 0 // a continuation of an interpolated string: no prefix
	}
	j := len(s)
	for j > i && isQuote(s[j-1]) {
		j--
	}
	return i, j
}

func blank(b []byte, from, to int) {
	for k := from; k < to; k++ {
		if b[k] != '\n' {
			b[k] = ' '
		}
	}
}

func isQuote(c byte) bool  { return c == '"' || c == '\'' || c == '`' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
