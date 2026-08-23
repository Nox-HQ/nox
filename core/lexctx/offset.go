package lexctx

// LineColToOffset converts a 1-based line and 1-based column into a 0-based
// byte offset into content. It is the bridge that lets analyzers which report
// findings by (line, column) — as Nox's rules engine does — feed those findings
// into the byte-oriented classifier without threading raw offsets through the
// whole pipeline.
//
// Columns are counted in bytes (not runes): the rules engine's Column is a byte
// column, so this stays consistent with it. A line or column past the end of
// content clamps to len(content); a non-positive line or column clamps to the
// start of the addressed line. The result is always in [0, len(content)].
func LineColToOffset(content []byte, line, col int) int {
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	n := len(content)
	// Walk to the start of the target line.
	offset := 0
	curLine := 1
	for offset < n && curLine < line {
		if content[offset] == '\n' {
			curLine++
		}
		offset++
	}
	// Advance col-1 bytes into the line, stopping at a newline or EOF.
	target := offset + (col - 1)
	if target > n {
		target = n
	}
	// Do not step past the end of this line into the next one.
	for i := offset; i < target && i < n; i++ {
		if content[i] == '\n' {
			return i
		}
	}
	return target
}

// LineForOffset returns the 1-based line number containing byte offset off. An
// offset past the end clamps to the end. It is the inverse direction of
// LineColToOffset and the one implementation two analyzers had each rolled.
func LineForOffset(content []byte, off int) int {
	if off > len(content) {
		off = len(content)
	}
	line := 1
	for i := 0; i < off; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}
