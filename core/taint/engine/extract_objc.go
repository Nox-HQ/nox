package engine

import "strings"

// extractObjC turns Objective-C (and Objective-C++) logical lines into unit
// drafts using the shared line/statement RECOGNIZER (never a real parser — only
// Go gets go/ast). Objective-C is C at its core — brace-delimited, `;`-terminated
// — so like the C/C++ recognizer it recognizes FUNCTION and METHOD definitions so
// each body becomes its own unit with its parameter list, feeding the
// interprocedural summary pass (a caller's Nth argument binds the callee's Nth
// parameter). Everything outside a function/method accumulates into the module
// unit.
//
// Objective-C adds two shapes a plain C recognizer does not have, handled here:
//
//   - BRACKET MESSAGE SENDS `[recv selector:arg ...]`. A message send IS a call:
//     the selector is the callee and the arguments are positional. Before the
//     shared recognizer runs, rewriteObjCMessageSends rewrites every message send
//     to the dotted call form `recv.selector(arg, ...)` the recognizer and the
//     catalog both understand — `[db executeQuery:sql]` becomes
//     `db.executeQuery(sql)` (callee suffix `executeQuery`), and a multi-keyword
//     selector `[v loadHTMLString:h baseURL:u]` becomes
//     `v.loadHTMLString(h, u)` keyed on the first-keyword suffix `loadHTMLString`.
//     Class-method sends (`[NSString stringWithContentsOfFile:p]`) and nested
//     sends (`[[Foo alloc] initWithData:d]`) fold the same way, innermost first.
//
//   - OBJC METHOD DEFINITIONS `- (ret)name:(T)arg ...` / `+ (ret)name`. The
//     instance (`-`) / class (`+`) method header opens a unit whose funcName is
//     the first selector keyword and whose params are the binding names.
//
// HONEST LIMITS (mirrored in the corpus README): like every non-Go language this
// is a line recognizer, so taint through a mutated object PROPERTY / ivar
// (`self.foo = tainted`, `_bar = tainted`) is not modeled as a bare-local
// binding; dynamic dispatch (`performSelector:`, `NSInvocation`) is invisible;
// and MEMORY-SAFETY bugs are a different analysis, out of scope for this engine.
func extractObjC(lines []logicalLine) []unitDraft {
	module := &unitDraft{funcName: ""}
	units := []*unitDraft{module}
	cur := module
	// depth is the block-brace nesting at the CURRENT logical line. A function/
	// method body opens at the header's `{`; when nesting falls back to the
	// header's depth the scope ends. funcDepth is -1 when not inside a recognized
	// function/method.
	depth := 0
	funcDepth := -1

	for idx := 0; idx < len(lines); idx++ {
		ll := rewriteObjCMessageSends(normalizeCPP(lines[idx]))
		trimmed := strings.TrimSpace(ll.code)
		if trimmed == "" {
			continue
		}

		// A `return ...;` line is a statement, never a definition header — check it
		// first so `return [self build:x];` (rewritten to `self.build(x)`) is not
		// misread as a header.
		if st, ok := objcReturnStatement(ll); ok {
			cur.stmts = append(cur.stmts, st)
			depth += braceDelta(trimmed)
			if funcDepth >= 0 && depth <= funcDepth {
				cur = module
				funcDepth = -1
			}
			continue
		}

		// An Objective-C METHOD definition header (`- (ret)name:(T)arg`) opens a
		// new unit. Recognized before the C function header and the generic
		// statement recognizer so its selector/parameter identifiers are never read
		// as a data-flow call.
		if name, params, ok := objcMethodHeader(trimmed); ok && cppHeaderHasBody(trimmed, lines, idx) {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funcDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		// A C function-DEFINITION header opens a new unit. Same rule as extractCPP:
		// a header is a definition only when a body brace `{` follows.
		if name, params, ok := cppFuncHeader(trimmed); ok && cppHeaderHasBody(trimmed, lines, idx) {
			u := &unitDraft{funcName: name, params: params}
			units = append(units, u)
			cur = u
			funcDepth = depth
			depth += braceDelta(trimmed)
			continue
		}

		if !isObjCStructuralLine(trimmed) {
			if st, ok := recognizeStatement(langCPP, ll); ok {
				applyCPPBufferBuilder(&st)
				cur.stmts = append(cur.stmts, st)
			}
		}

		depth += braceDelta(trimmed)
		if funcDepth >= 0 && depth <= funcDepth {
			cur = module
			funcDepth = -1
		}
	}

	out := make([]unitDraft, 0, len(units))
	for _, u := range units {
		out = append(out, *u)
	}
	return out
}

// objcReturnStatement recognizes a `return <expr>;` line (after message-send
// rewrite) and produces a stmtDraft whose `returns` lists the returned variable
// names while still capturing the calls/reads in the returned expression (so
// `return [NSString stringWithContentsOfFile:p];` — rewritten to
// `NSString.stringWithContentsOfFile(p)` — is both a sink read AND a return). It
// reuses the C/C++ return recognizer since, post-rewrite, the expression is
// ordinary dotted-call C syntax.
func objcReturnStatement(ll logicalLine) (stmtDraft, bool) {
	return cppReturnStatement(ll)
}

// isObjCStructuralLine reports whether a line is block/scaffolding whose tokens
// must not be read as a data-flow statement. It extends the C/C++ structural set
// with Objective-C declaration keywords (`@interface`, `@implementation`,
// `@property`, `@synthesize`, `@end`, `@class`, `@protocol`, `@import`,
// `@autoreleasepool`) and a lone `-`/`+` method-sigil line. Intentionally coarse
// — a missed skip only adds a harmless non-sink call to the enclosing unit.
func isObjCStructuralLine(trimmed string) bool {
	if isCPPStructuralLine(trimmed) {
		return true
	}
	for _, kw := range []string{
		"@interface", "@implementation", "@property", "@synthesize", "@dynamic",
		"@end", "@class", "@protocol", "@import", "@autoreleasepool", "@try",
		"@catch", "@finally", "@synchronized",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// objcMethodHeader returns the method name and its positional parameter binding
// names when trimmed is an Objective-C method DEFINITION header:
//
//   - (ReturnType)selector
//   - (ReturnType)selectorWith:(T)arg andThis:(U)other
//   - (instancetype)classMethod:(T)arg
//
// The method name is the FIRST selector keyword (`selectorWith` above) — the same
// suffix a rewritten call `[obj selectorWith:x andThis:y]` keys on. Each
// `keyword:(Type)binding` contributes the binding name in declaration order; a
// no-argument selector yields no parameters. Reports ok=false for anything that
// is not a `-`/`+` method header.
func objcMethodHeader(trimmed string) (name string, params []string, ok bool) {
	if !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "+") {
		return "", nil, false
	}
	rest := strings.TrimSpace(trimmed[1:])
	// A `(ReturnType)` group must follow the sigil.
	if !strings.HasPrefix(rest, "(") {
		return "", nil, false
	}
	closeIdx := matchParen(rest, 0)
	if closeIdx < 0 {
		return "", nil, false
	}
	rest = strings.TrimSpace(rest[closeIdx+1:])
	// Drop a trailing body brace and any trailing method attributes/whitespace.
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "{"))
	if rest == "" {
		return "", nil, false
	}
	segments := objcSelectorSegments(rest)
	if len(segments) == 0 {
		return "", nil, false
	}
	name = segments[0].keyword
	if !isSimpleIdent(name) {
		return "", nil, false
	}
	for _, seg := range segments {
		if seg.binding != "" && isSimpleIdent(seg.binding) && !isKeyword(seg.binding) {
			params = append(params, seg.binding)
		}
	}
	return name, params, true
}

// objcSelectorSeg is one `keyword:(Type)binding` piece of a method-definition
// selector. For a no-argument selector the whole selector is a single segment
// with an empty binding.
type objcSelectorSeg struct {
	keyword string
	binding string
}

// objcSelectorSegments splits a method-definition selector body (everything after
// the `- (ReturnType)`) into its keyword/binding segments. `run` yields one
// segment {run, ""}; `runWith:(NSString *)cmd andArg:(int)n` yields
// {runWith, cmd} and {andArg, n}. It walks keyword identifiers, consumes a
// `:(Type)` group, then reads the binding identifier up to the next keyword.
func objcSelectorSegments(body string) []objcSelectorSeg {
	body = strings.TrimSpace(body)
	// No-argument selector: a bare identifier with no ':'.
	if !strings.Contains(body, ":") {
		if isSimpleIdent(body) {
			return []objcSelectorSeg{{keyword: body}}
		}
		// Take the leading identifier defensively.
		kw := leadingIdent(body)
		if kw == "" {
			return nil
		}
		return []objcSelectorSeg{{keyword: kw}}
	}

	var segs []objcSelectorSeg
	i := 0
	n := len(body)
	for i < n {
		// Skip whitespace.
		for i < n && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		// Read a keyword identifier.
		start := i
		for i < n && isIdentPart(body[i]) {
			i++
		}
		keyword := body[start:i]
		if keyword == "" {
			break
		}
		// Expect ':' — otherwise this trailing token is not a keyword arg.
		for i < n && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i >= n || body[i] != ':' {
			// A trailing identifier with no colon: treat as a no-arg keyword only if
			// it is the first segment (a bare selector already handled above).
			if len(segs) == 0 {
				segs = append(segs, objcSelectorSeg{keyword: keyword})
			}
			break
		}
		i++ // past ':'
		// Skip a `(Type)` group.
		for i < n && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i < n && body[i] == '(' {
			closeIdx := matchParen(body, i)
			if closeIdx < 0 {
				break
			}
			i = closeIdx + 1
		}
		// Read the binding identifier.
		for i < n && (body[i] == ' ' || body[i] == '\t' || body[i] == '*' || body[i] == '&') {
			i++
		}
		bStart := i
		for i < n && isIdentPart(body[i]) {
			i++
		}
		binding := body[bStart:i]
		segs = append(segs, objcSelectorSeg{keyword: keyword, binding: binding})
	}
	return segs
}

// leadingIdent returns the leading identifier of s (letters/underscore run), or
// "" if s does not begin with an identifier byte.
func leadingIdent(s string) string {
	i := 0
	for i < len(s) && isIdentPart(s[i]) {
		i++
	}
	return s[:i]
}

// rewriteObjCMessageSends rewrites every bracket message send in a logical line
// to the equivalent dotted-call form so the shared recognizer and the catalog
// see an ordinary call. `[recv selector:arg]` becomes `recv.selector(arg)`;
// `[recv kw1:a kw2:b]` becomes `recv.kw1(a, b)` (keyed on the first-keyword
// suffix); `[recv method]` becomes `recv.method()`; nested sends are rewritten
// innermost-first. The identical structural rewrite is applied to BOTH the code
// and raw views, so they stay equal length and byte-aligned to each other (all
// recognizeStatement/argInfo require) — the code view drives the parse (its
// delimiters are code bytes present identically in raw) and each view's token
// bytes are copied from its own source.
func rewriteObjCMessageSends(ll logicalLine) logicalLine {
	code := ll.code
	raw := ll.raw
	aligned := len(code) == len(raw)
	for {
		open, closeIdx := innermostMessageSend(code)
		if open < 0 {
			break
		}
		newCode, newRaw, ok := rewriteOneSend(code, raw, open, closeIdx, aligned)
		if !ok {
			// Could not parse this send; blank its brackets to spaces so the loop
			// terminates and the recognizer is not confused by stray `[`/`]`.
			code = replaceAt(code, open, ' ')
			code = replaceAt(code, closeIdx, ' ')
			if aligned {
				raw = replaceAt(raw, open, ' ')
				raw = replaceAt(raw, closeIdx, ' ')
			}
			continue
		}
		code = newCode
		if aligned {
			raw = newRaw
		}
	}
	if !aligned {
		raw = code // fall back to the code view so downstream stays consistent
	}
	return logicalLine{line: ll.line, code: code, raw: raw}
}

// innermostMessageSend returns the byte offsets of the opening `[` and closing
// `]` of the FIRST innermost message send in code (a `[...]` group containing no
// nested `[`), or (-1,-1) when there is none. Scanning innermost-first lets
// nested sends `[[a b] c]` be rewritten from the inside out. A `[...]` that is a
// C array subscript (`arr[i]`) is skipped: a subscript's `[` immediately follows
// an identifier/`)`/`]` byte, whereas a message send's `[` opens a new primary
// expression.
func innermostMessageSend(code string) (open, closeIdx int) {
	n := len(code)
	for i := 0; i < n; i++ {
		if code[i] != '[' {
			continue
		}
		// Skip array subscripts: `[` right after an identifier/close-bracket byte.
		if i > 0 {
			prev := code[i-1]
			if isIdentPart(prev) || prev == ')' || prev == ']' {
				continue
			}
		}
		// Find the matching `]`, and confirm there is no nested `[` (innermost).
		depth := 0
		for j := i; j < n; j++ {
			switch code[j] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					if !strings.Contains(code[i+1:j], "[") {
						return i, j
					}
					// Not innermost; continue the outer scan past this `[`.
					j = n
				}
			}
		}
	}
	return -1, -1
}

// rewriteOneSend rewrites a single innermost message send `code[open..closeIdx]`
// (`[recv selector:args...]`) into the dotted call `recv.selector(args)` in both
// views, returning the rewritten strings. It returns ok=false when the span is
// not a well-formed message send (e.g. an array literal `@[...]` or a malformed
// group), letting the caller blank the brackets and move on. The receiver is the
// leading primary expression; the selector keywords are folded so the callee is
// `recv.firstKeyword` and the arguments are gathered positionally.
func rewriteOneSend(code, raw string, open, closeIdx int, aligned bool) (newCode, newRaw string, ok bool) {
	inner := code[open+1 : closeIdx]
	// An `@[...]`/`@{...}` collection literal is not a message send: the byte
	// before `[` is `@`. innermostMessageSend already skips subscripts; guard the
	// `@` collection form here.
	if open > 0 && code[open-1] == '@' {
		return "", "", false
	}
	recvEnd, selStart := splitReceiverSelector(inner)
	if recvEnd <= 0 {
		return "", "", false
	}
	receiver := strings.TrimSpace(inner[:recvEnd])
	if receiver == "" {
		return "", "", false
	}
	selBody := inner[selStart:]
	callee, argSpans, parsed := parseSelectorCall(selBody, selStart)
	if !parsed {
		return "", "", false
	}

	// Build the replacement text `receiver.callee(arg0, arg1, ...)` for each view.
	buildRepl := func(src string) string {
		var b strings.Builder
		b.WriteString(receiver)
		b.WriteByte('.')
		b.WriteString(callee)
		b.WriteByte('(')
		for k, span := range argSpans {
			if k > 0 {
				b.WriteString(", ")
			}
			// span offsets are relative to inner; map into src via open+1.
			b.WriteString(strings.TrimSpace(src[open+1+span[0] : open+1+span[1]]))
		}
		b.WriteByte(')')
		return b.String()
	}

	newCode = code[:open] + buildRepl(code) + code[closeIdx+1:]
	newRaw = raw
	if aligned {
		newRaw = raw[:open] + buildRepl(raw) + raw[closeIdx+1:]
	}
	return newCode, newRaw, true
}

// splitReceiverSelector splits a message-send interior `recv selectorBody` into
// the receiver end offset and the selector start offset. The receiver is the
// leading primary expression (an identifier, a dotted chain, or an
// already-rewritten `x.y(z)` from an inner send); the selector begins at the
// next identifier after the separating whitespace. Returns (recvEnd, selStart)
// as offsets into inner, or (0,0) when no separating space is found.
func splitReceiverSelector(inner string) (recvEnd, selStart int) {
	n := len(inner)
	i := 0
	// Skip leading whitespace.
	for i < n && (inner[i] == ' ' || inner[i] == '\t') {
		i++
	}
	// Consume the receiver: a balanced run up to the first TOP-LEVEL whitespace.
	depth := 0
	recvEnd = -1
	for ; i < n; i++ {
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ' ', '\t':
			if depth == 0 {
				recvEnd = i
			}
		}
		if recvEnd >= 0 {
			break
		}
	}
	if recvEnd <= 0 {
		return 0, 0
	}
	selStart = recvEnd
	for selStart < n && (inner[selStart] == ' ' || inner[selStart] == '\t') {
		selStart++
	}
	return recvEnd, selStart
}

// parseSelectorCall parses a selector body `kw1:arg1 kw2:arg2 ...` (or a
// no-argument selector `method`) into the callee (the FIRST keyword) and the
// argument spans (each [start,end) offset relative to the ORIGINAL inner string;
// baseOffset is the selector body's start within inner). It returns ok=false for
// a malformed selector. A no-argument selector yields the bare method name and no
// args.
func parseSelectorCall(selBody string, baseOffset int) (callee string, argSpans [][2]int, ok bool) {
	// No-argument selector.
	if !strings.Contains(selBody, ":") {
		name := leadingIdent(strings.TrimSpace(selBody))
		if name == "" {
			return "", nil, false
		}
		return name, nil, true
	}
	n := len(selBody)
	i := 0
	first := true
	for i < n {
		for i < n && (selBody[i] == ' ' || selBody[i] == '\t') {
			i++
		}
		// Read keyword identifier.
		kwStart := i
		for i < n && isIdentPart(selBody[i]) {
			i++
		}
		keyword := selBody[kwStart:i]
		// Expect ':'.
		for i < n && (selBody[i] == ' ' || selBody[i] == '\t') {
			i++
		}
		if i >= n || selBody[i] != ':' {
			break
		}
		i++ // past ':'
		if first {
			if keyword == "" {
				return "", nil, false
			}
			callee = keyword
			first = false
		}
		// Read the argument value: a balanced run up to the next TOP-LEVEL
		// `keyword:` boundary or end of selector.
		for i < n && (selBody[i] == ' ' || selBody[i] == '\t') {
			i++
		}
		argStart := i
		depth := 0
		done := false
		for i < n && !done {
			switch c := selBody[i]; {
			case c == '(' || c == '[' || c == '{':
				depth++
			case c == ')' || c == ']' || c == '}':
				depth--
			case depth == 0 && (c == ' ' || c == '\t') && isNextKeywordArg(selBody, i):
				// A whitespace boundary before the next `keyword:` ends this argument.
				done = true
			}
			if !done {
				i++
			}
		}
		argEnd := i
		argSpans = append(argSpans, [2]int{baseOffset + argStart, baseOffset + argEnd})
	}
	if callee == "" {
		return "", nil, false
	}
	return callee, argSpans, true
}

// isNextKeywordArg reports whether, starting at whitespace offset i in selBody,
// the following token is a `keyword:` label (the boundary between two message
// arguments) rather than a continuation of the current argument expression.
func isNextKeywordArg(selBody string, i int) bool {
	j := i
	n := len(selBody)
	for j < n && (selBody[j] == ' ' || selBody[j] == '\t') {
		j++
	}
	kwStart := j
	for j < n && isIdentPart(selBody[j]) {
		j++
	}
	if j == kwStart {
		return false
	}
	for j < n && (selBody[j] == ' ' || selBody[j] == '\t') {
		j++
	}
	return j < n && selBody[j] == ':'
}

// replaceAt returns s with the byte at index i replaced by c (i in range).
func replaceAt(s string, i int, c byte) string {
	if i < 0 || i >= len(s) {
		return s
	}
	b := []byte(s)
	b[i] = c
	return string(b)
}
