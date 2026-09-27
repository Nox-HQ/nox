package secrets

// unescapeNotebookQuotes returns a copy of a notebook in which every JSON-
// escaped quote \" reads as a quote preceded by a space.
//
// A notebook stores each line of a cell as a JSON string, so the cell's
// api_key="..." is api_key=\"...\" on disk, and a rule that expects a quote
// right against the value never matches it. Each two-byte \" becomes a quote
// plus a space, the space on the outside of the string: ` "` for an opening
// quote, `" ` for a closing one (the byte before it belongs to the value). The
// length is unchanged, so every line and column stays where it is in the file,
// findings point at the file on disk, and the refiners that re-read a span
// from content see the bytes the rules matched. Only notebooks get this: in
// other JSON an escaped quote is data (a recorded request body), not code.
func unescapeNotebookQuotes(content []byte) []byte {
	out := make([]byte, len(content))
	copy(out, content)
	for i := 0; i+1 < len(out); i++ {
		switch {
		case out[i] == '\\' && out[i+1] == '\\':
			i++ // an escaped backslash; the byte after it is not an escape
		case out[i] == '\\' && out[i+1] == '"':
			if i > 0 && isValueByte(out[i-1]) {
				out[i], out[i+1] = '"', ' '
			} else {
				out[i] = ' '
			}
			i++
		}
	}
	return out
}

// isValueByte reports whether b can end a credential value, which makes the
// escaped quote after it a closing one. `=` is left out: before a quote it
// is almost always the assignment, not base64 padding.
func isValueByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '-' || b == '_' || b == '.' || b == '/' || b == '+'
}
