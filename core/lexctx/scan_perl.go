package lexctx

// scanPerl walks Perl source and classifies each byte as code, string, or
// comment. Perl is famously the hardest mainstream language to lex without a
// full interpreter (its grammar is Turing-undecidable in the general case), so
// this is a deliberately PRAGMATIC, deterministic classifier. It recognizes the
// constructs that carry the overwhelming majority of secret/pattern and taint
// false positives, and every heuristic degrades safely: a misread only costs
// FP-suppression, never correctness, because an over-broad code region merely
// disables suppression.
//
// Recognized constructs:
//
//   - `#` line comments (to end of line) — but NOT `$#array` (the last-index
//     sigil), where the `#` is part of a special variable, and not a `#` inside
//     a string, which the string scanner consumes first. A `#` inside a regex
//     character class is handled only best-effort (regex lexing is pragmatic).
//   - POD blocks: a `=pod` / `=head1` / `=item` / any `=word` directive that
//     starts at column 0 opens a documentation block that runs (as one comment)
//     through the line beginning `=cut`. Perl requires the `=` at column 0, and
//     the classifier enforces that so an indented `=` never swallows the file.
//   - single-quoted strings `'...'` — no interpolation; only `\\` and `\'` are
//     escapes.
//   - double-quoted strings `"..."` — backslash escapes AND `$var` / `@var`
//     interpolation, whose fields are emitted as CODE (a tainted value spliced
//     via "id=$id" lives in a real expression).
//   - backtick command strings “ `...` “ — lexed like a double-quoted string
//     (they interpolate); the taint layer treats the backtick itself as a
//     command-execution sink.
//   - quote-like operators `q(...)` (single), `qq(...)` (double), `qw(...)`
//     (word list), `qx(...)` (command) with matched-bracket or arbitrary
//     single-char delimiters; the interpolating variants (qq, qx) emit `$var`
//     fields as code, the non-interpolating (q, qw) keep the whole body string.
//   - heredocs `<<"EOF"` / `<<'EOF'` / `<<~EOF` / `<<EOF`: the body runs from the
//     next line to a line whose (optionally trimmed, for `<<~`) content equals
//     the terminator. The body is emitted as string; `<<"…"` and bare `<<EOF`
//     interpolate (but for simplicity the heredoc body is kept whole-string —
//     heredoc interpolation is rare as a taint carrier and treating the body as
//     string is the safe, FP-suppressing choice).
//   - regex `m/.../`, `s/.../.../`, `tr/.../.../` and a bare `/.../ ` match are
//     handled best-effort as string-kind, disambiguated from `/` division by the
//     preceding significant token; a `/` in operand position is a regex, after
//     an operand it is division. This is intentionally coarse — Perl regex
//     lexing is undecidable, and a misread only costs suppression.
//
// Like the other scanners it emits strictly increasing, contiguous spans into a
// regionBuilder so the returned regions are gap-free and cover [0, len(content)).
func scanPerl(content []byte) []Region {
	var b regionBuilder
	i := 0
	n := len(content)
	// prevSignificant is the last non-space code byte emitted — it drives the
	// regex-vs-division heuristic. 0 means "start of file / after a newline".
	var prevSignificant byte
	// atColumnZero is true when the cursor sits at the first byte of a physical
	// line. POD `=` directives must start at column 0.
	atColumnZero := true

	for i < n {
		c := content[i]

		// POD block: a `=` at column 0 immediately followed by an identifier
		// letter opens a documentation block that runs through a `=cut` line.
		if atColumnZero && c == '=' && i+1 < n && isPerlPodDirectiveStart(content[i+1]) {
			end := scanPerlPod(content, i)
			b.emit(i, end, KindComment)
			i = end
			atColumnZero = true
			prevSignificant = 0
			continue
		}

		atColumnZero = false

		switch {
		case c == '#' && !isPerlArrayLenSigil(content, i):
			start := i
			for i < n && content[i] != '\n' {
				i++
			}
			b.emit(start, i, KindComment)
		case c == '\n':
			b.emit(i, i+1, KindCode)
			i++
			atColumnZero = true
			prevSignificant = 0
			continue
		case c == '\'':
			end := scanPerlSingleQuote(content, i)
			b.emit(i, end, KindString)
			i = end
			prevSignificant = '\''
		case c == '"':
			i = scanPerlInterpolated(content, i, '"', &b)
			prevSignificant = '"'
		case c == '`':
			i = scanPerlInterpolated(content, i, '`', &b)
			prevSignificant = '`'
		case isPerlQuoteLikeStart(content, i, prevSignificant):
			i = scanPerlQuoteLike(content, i, &b)
			prevSignificant = ')'
		case c == '<' && i+1 < n && content[i+1] == '<' && isPerlHeredocStart(content, i, prevSignificant):
			i = scanPerlHeredoc(content, i, &b)
			atColumnZero = true
			prevSignificant = 0
			continue
		case c == '/' && isPerlRegexStart(prevSignificant):
			end := scanPerlRegex(content, i)
			b.emit(i, end, KindString)
			i = end
			prevSignificant = '/'
		default:
			b.emit(i, i+1, KindCode)
			if c != ' ' && c != '\t' && c != '\r' {
				prevSignificant = c
			}
			i++
			continue
		}
	}
	return b.finish(n)
}

// isPerlPodDirectiveStart reports whether b can begin a POD directive name after
// the leading `=` (a letter). `=cut` itself, `=head1`, `=pod`, `=over`, etc. all
// begin with a letter; `= ` (assignment spacing) or `==` do not.
func isPerlPodDirectiveStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isPerlArrayLenSigil reports whether the `#` at i is the `$#array` last-index
// sigil (or `$#{...}`) rather than a comment. It is the sigil when the preceding
// byte is `$`.
func isPerlArrayLenSigil(content []byte, i int) bool {
	return i > 0 && content[i-1] == '$'
}

// scanPerlPod returns the offset just past a POD block whose `=directive` starts
// at start (column 0). The block ends at the newline following a line that
// starts with `=cut` at column 0; an unterminated block runs to EOF.
func scanPerlPod(content []byte, start int) int {
	n := len(content)
	// Advance to the end of the opening directive line.
	i := start
	for i < n && content[i] != '\n' {
		i++
	}
	for i < n {
		lineStart := i + 1
		if lineStart >= n {
			return n
		}
		if hasWordAt(content, lineStart, "=cut") {
			j := lineStart
			for j < n && content[j] != '\n' {
				j++
			}
			if j < n {
				j++ // include the trailing newline
			}
			return j
		}
		j := lineStart
		for j < n && content[j] != '\n' {
			j++
		}
		i = j
	}
	return n
}

// scanPerlSingleQuote returns the offset just past a single-quoted string opening
// at start. Only `\\` and `\'` are escapes; every other byte (incl. newlines) is
// literal. An unterminated literal runs to EOF.
func scanPerlSingleQuote(content []byte, start int) int {
	n := len(content)
	i := start + 1
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			return i + 1
		}
		i++
	}
	return n
}

// scanPerlInterpolated classifies a double-quoted or backtick string opening at
// start, emitting the literal parts as string and each `$var` / `@var`
// interpolation as code. closeByte is the closing delimiter. Backslash escapes
// suppress interpolation of the next byte. Returns the offset just past the
// closing delimiter (or EOF).
func scanPerlInterpolated(content []byte, start int, closeByte byte, b *regionBuilder) int {
	n := len(content)
	bodyStart := start + 1
	b.emit(start, bodyStart, KindString)
	i := bodyStart
	runStart := bodyStart
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if c == closeByte {
			b.emit(runStart, i+1, KindString)
			return i + 1
		}
		if (c == '$' || c == '@') && i+1 < n && isPerlInterpVarStart(content[i+1]) {
			// Flush the literal run, emit the interpolation field as code.
			b.emit(runStart, i, KindString)
			fieldEnd := scanPerlInterpField(content, i)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// isPerlInterpVarStart reports whether b can begin an interpolated variable name
// after a `$`/`@` sigil: a letter, underscore, or `{` (for `${...}` / `@{...}`).
// A digit ($1) or punctuation special var is treated as non-interpolating here
// (pragmatic — those are rarely taint carriers) so `$1` in a string stays string.
func isPerlInterpVarStart(b byte) bool {
	return b == '_' || b == '{' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// scanPerlInterpField returns the offset just past a `$var` / `@var` /
// `${...}` interpolation field whose sigil is at start. It consumes the sigil,
// an optional `{...}` (balanced) or an identifier, and any trailing element
// access chain (`->{k}`, `[i]`, `{k}`, `->method`) so the whole lvalue is code.
func scanPerlInterpField(content []byte, start int) int {
	n := len(content)
	i := start + 1 // past the sigil
	if i < n && content[i] == '{' {
		// ${ ... } — balance braces.
		depth := 0
		for i < n {
			switch content[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					i++
					return scanPerlAccessChain(content, i)
				}
			}
			i++
		}
		return n
	}
	// Bare identifier (possibly with :: package separators).
	for i < n && (isPerlIdentByte(content[i]) || (content[i] == ':' && i+1 < n && content[i+1] == ':')) {
		if content[i] == ':' {
			i += 2
			continue
		}
		i++
	}
	return scanPerlAccessChain(content, i)
}

// scanPerlAccessChain consumes a trailing element/hash-access chain after a
// variable name inside an interpolation — `[expr]`, `{key}`, `->[i]`, `->{k}` —
// so the entire interpolated lvalue is treated as one code field. It stops at
// the first byte that cannot continue such a chain.
func scanPerlAccessChain(content []byte, i int) int {
	n := len(content)
	for i < n {
		switch {
		case content[i] == '-' && i+1 < n && content[i+1] == '>':
			i += 2
		case content[i] == '[' || content[i] == '{':
			open := content[i]
			closeByte := byte(']')
			if open == '{' {
				closeByte = '}'
			}
			depth := 0
			for i < n {
				if content[i] == open {
					depth++
				} else if content[i] == closeByte {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				i++
			}
		default:
			return i
		}
	}
	return i
}

// isPerlQuoteLikeStart reports whether the bytes at i begin a `q`/`qq`/`qw`/`qx`
// quote-like operator rather than an ordinary identifier. It fires when the
// token is exactly one of those operators, it is in an operand position (not
// after an identifier byte or a closing bracket — where it would be a method
// name or a variable), and it is followed (after optional spaces) by a
// delimiter byte.
func isPerlQuoteLikeStart(content []byte, i int, prev byte) bool {
	// After an operand, `q...` is an identifier, not a quote-like.
	if isPerlIdentByte(prev) {
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	}
	n := len(content)
	if content[i] != 'q' {
		return false
	}
	j := i + 1
	// Optional second letter: q, qq, qw, qx, qr.
	if j < n {
		switch content[j] {
		case 'q', 'w', 'x', 'r':
			j++
		}
	}
	// The operator name must end here — the next byte must not continue an
	// identifier (else `queue`, `question` are mis-detected).
	if j < n && isPerlIdentByte(content[j]) {
		return false
	}
	// Skip whitespace between the operator and its delimiter.
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	if j >= n {
		return false
	}
	return isPerlQuoteDelim(content[j])
}

// isPerlQuoteDelim reports whether c can open a quote-like body. Perl allows any
// non-alphanumeric, non-whitespace byte; we accept the common bracket pairs and
// the usual punctuation delimiters.
func isPerlQuoteDelim(c byte) bool {
	switch c {
	case '(', '[', '{', '<', '/', '|', '!', '#', '~', '"', '\'', ',', '.', ':', ';', '%', '*':
		return true
	}
	return false
}

// scanPerlQuoteLike returns the offset just past a quote-like operator opening at
// start. It emits the operator, delimiters, and body as string, EXCEPT that an
// INTERPOLATING variant (qq, qx, qr) emits each `$var`/`@var` field as code.
// Paired-bracket delimiters nest; a backslash escapes the delimiter. Unterminated
// runs to EOF.
func scanPerlQuoteLike(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	j := start + 1 // past 'q'
	interp := false
	if j < n {
		switch content[j] {
		case 'q', 'x', 'r': // qq, qx, qr interpolate
			interp = true
			j++
		case 'w': // qw does not interpolate
			j++
		}
	}
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	if j >= n {
		b.emit(start, n, KindString)
		return n
	}
	open := content[j]
	closeByte := perlQuoteCloser(open)
	nested := open != closeByte
	depth := 1
	i := j + 1
	runStart := start // the whole operator + delimiters are string
	for i < n {
		c := content[i]
		if c == '\\' {
			i += 2
			continue
		}
		if interp && (c == '$' || c == '@') && i+1 < n && isPerlInterpVarStart(content[i+1]) {
			b.emit(runStart, i, KindString)
			fieldEnd := scanPerlInterpField(content, i)
			b.emit(i, fieldEnd, KindCode)
			i = fieldEnd
			runStart = i
			continue
		}
		if nested && c == open {
			depth++
		} else if c == closeByte {
			depth--
			if depth == 0 {
				b.emit(runStart, i+1, KindString)
				return i + 1
			}
		}
		i++
	}
	b.emit(runStart, n, KindString)
	return n
}

// perlQuoteCloser returns the closing delimiter for a quote-like opener. Paired
// brackets have a distinct closer; every other delimiter is its own closer.
func perlQuoteCloser(open byte) byte {
	switch open {
	case '(':
		return ')'
	case '[':
		return ']'
	case '{':
		return '}'
	case '<':
		return '>'
	}
	return open
}

// isPerlHeredocStart reports whether `<<` at i begins a heredoc rather than a
// left-shift operator. A heredoc marker is `<<`, then an optional `~`, then a
// quoted or bare terminator that starts with a letter/underscore or a quote — and
// it only appears in an operand position (not after an identifier/number/close
// bracket, where `<<` is left-shift).
func isPerlHeredocStart(content []byte, i int, prev byte) bool {
	if isPerlIdentByte(prev) {
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	}
	n := len(content)
	j := i + 2 // past `<<`
	if j < n && content[j] == '~' {
		j++
	}
	if j >= n {
		return false
	}
	if content[j] == '"' || content[j] == '\'' || content[j] == '`' {
		return j+1 < n && isPerlIdentStart(content[j+1])
	}
	// A bare `<< IDENT` heredoc; but `<<2` (shift) or `<< $x` are not heredocs.
	return isPerlIdentStart(content[j])
}

// scanPerlHeredoc classifies a heredoc opening at start. The `<<TERM` opener (and
// any same-line code up to the newline, e.g. `my $x = <<"EOF"; # comment`) is
// emitted as CODE; the body — the lines from the next line up to (and including)
// the terminator line — is emitted as string. Indented (`<<~`) heredocs allow an
// indented terminator. The body is kept whole-string (heredoc interpolation is
// not split — the safe, FP-suppressing choice for a rare taint carrier).
func scanPerlHeredoc(content []byte, start int, b *regionBuilder) int {
	n := len(content)
	j := start + 2 // past `<<`
	indented := false
	if j < n && content[j] == '~' {
		indented = true
		j++
	}
	var term []byte
	if j < n && (content[j] == '"' || content[j] == '\'' || content[j] == '`') {
		q := content[j]
		j++
		tStart := j
		for j < n && content[j] != q {
			j++
		}
		term = content[tStart:j]
		if j < n {
			j++ // past the closing quote
		}
	} else {
		tStart := j
		for j < n && isPerlIdentByte(content[j]) {
			j++
		}
		term = content[tStart:j]
	}
	// Emit the opener line (through its trailing newline) as code.
	lineEnd := j
	for lineEnd < n && content[lineEnd] != '\n' {
		lineEnd++
	}
	if lineEnd < n {
		lineEnd++ // include the newline
	}
	b.emit(start, lineEnd, KindCode)

	bodyStart := lineEnd
	i := lineEnd
	for i < n {
		ls := i
		le := i
		for le < n && content[le] != '\n' {
			le++
		}
		lineBytes := content[ls:le]
		if isHeredocTerminator(lineBytes, term, indented) {
			if ls > bodyStart {
				b.emit(bodyStart, ls, KindString)
			}
			termEnd := le
			if termEnd < n {
				termEnd++
			}
			b.emit(ls, termEnd, KindCode)
			return termEnd
		}
		i = le
		if i < n {
			i++
		}
	}
	if n > bodyStart {
		b.emit(bodyStart, n, KindString)
	}
	return n
}

// isPerlRegexStart reports whether a `/` following prev begins a regex literal
// rather than division. Heuristic like Ruby's: a regex may only begin in operand
// position — start of line (prev == 0) or after an operator/opener. After an
// identifier byte, digit, or closing bracket, `/` is division.
func isPerlRegexStart(prev byte) bool {
	switch {
	case prev == 0:
		return true
	case isPerlIdentByte(prev):
		return false
	}
	switch prev {
	case ')', ']', '}':
		return false
	case '=', '(', ',', '|', '&', '!', '<', '>', '+', '-', '*', '%', '~', '?', ':', ';', '{', '[':
		return true
	}
	return false
}

// scanPerlRegex returns the offset just past a `/.../ ` regex literal opening at
// start, honoring backslash escapes and skipping character classes `[...]`. A
// newline terminates an unterminated regex defensively.
func scanPerlRegex(content []byte, start int) int {
	n := len(content)
	i := start + 1
	inClass := false
	for i < n {
		switch content[i] {
		case '\\':
			i += 2
			continue
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				j := i + 1
				for j < n && isPerlIdentByte(content[j]) {
					j++ // trailing flags (imsxg…)
				}
				return j
			}
		case '\n':
			return i
		}
		i++
	}
	return n
}

// isPerlIdentStart reports whether b can begin a Perl identifier.
func isPerlIdentStart(b byte) bool { return asciiIdentStart(b) }

// isPerlIdentByte reports whether b can appear inside a Perl identifier.
func isPerlIdentByte(b byte) bool { return asciiIdentPart(b) }
