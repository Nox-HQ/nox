package engine

import "strings"

// langKind selects the small syntactic differences between the two supported
// languages (assignment keywords, call-chain punctuation). Everything else in
// recognition is shared.
type langKind int

const (
	langPython langKind = iota
	langJavaScript
	langPHP
	langJava
	langRuby
	langRust
	langCSharp
)

// recognizeStatement turns one logical line into a stmtDraft, or reports ok=false
// when the line is not one of the two shapes we model (an assignment or a
// call-bearing statement). It never panics on malformed input — unrecognized
// syntax simply yields no statement, which is the safe degrade (a missed flow,
// never a crash or a spurious finding).
func recognizeStatement(lang langKind, ll logicalLine) (st stmtDraft, ok bool) {
	code := ll.code
	st.line = ll.line
	st.sinkArgs = map[string]sinkArgDraft{}

	lhs, rhs := splitAssignment(lang, code)
	if lhs != "" {
		st.assigns = lhs
	}
	exprCode := code
	// rawExpr is the raw (un-blanked) text aligned to exprCode by byte offset,
	// so argument counting can tell a string-literal argument (blanked to spaces
	// in the code view) from an absent argument.
	rawExpr := ll.raw
	if lhs != "" {
		// Align both views to the RHS by trimming the same prefix length. The
		// code and raw strings share offsets, so cut raw at the code's rhs start.
		if idx := strings.Index(code, rhs); idx >= 0 && idx+len(rhs) <= len(rawExpr) {
			rawExpr = ll.raw[idx : idx+len(rhs)]
		}
		exprCode = rhs
	}

	// Extract every call chain and its argument text from the expression side.
	calls := extractCalls(lang, exprCode, rawExpr)
	for i := range calls {
		st.calls = append(st.calls, calls[i].callee)
	}

	// Reads = variable names referenced in the expression (identifiers that are
	// not immediately followed by a call paren, i.e. not the callee itself, plus
	// bare identifiers). We union all argument reads and free identifier reads.
	reads := map[string]struct{}{}
	for _, id := range freeIdentifiers(lang, exprCode) {
		reads[id] = struct{}{}
	}
	for i := range calls {
		info := argInfo(lang, calls[i])
		for _, v := range info.taintedArgVars {
			reads[v] = struct{}{}
		}
		st.sinkArgs[calls[i].callee] = info
	}
	for r := range reads {
		st.reads = append(st.reads, r)
	}
	sortStrings(st.reads)

	st.chains = dottedChains(exprCode)

	if st.assigns == "" && len(st.calls) == 0 && len(st.reads) == 0 {
		return stmtDraft{}, false
	}
	return st, true
}

// splitAssignment splits an assignment into (lhs var, rhs expr). It recognizes a
// single top-level `=` (not `==`, `!=`, `<=`, `>=`, `:=`, or augmented ops like
// `+=`), outside any bracket, and requires a bare identifier LHS (dotted or
// subscripted targets are treated as non-assignments — their taint tracking
// needs field/element sensitivity we do not claim). Returns ("","") when the
// line is not a simple assignment.
func splitAssignment(lang langKind, code string) (lhs, rhs string) {
	depth := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			// Skip comparison/compound operators.
			if i+1 < len(code) && code[i+1] == '=' {
				i++
				continue
			}
			if i > 0 {
				switch code[i-1] {
				case '=', '!', '<', '>', ':', '+', '-', '*', '/', '%', '&', '|', '^':
					continue
				}
			}
			left := strings.TrimSpace(code[:i])
			right := strings.TrimSpace(code[i+1:])
			// JS declaration keywords.
			if lang == langJavaScript {
				left = stripDeclKeyword(left)
			}
			// Java variable declarations put a type before the name
			// (`String user = ...`, `final int n = ...`, `Map<String,String> m = ...`).
			// Strip the leading type/modifiers so the bare declared name is the LHS.
			if lang == langJava {
				left = stripJavaDeclType(left)
			}
			// Rust `let` / `let mut` binding keywords, plus a trailing `: Type`
			// annotation on the binding (`let x: String = ...`).
			if lang == langRust {
				left = stripRustLetKeyword(left)
			}
			// C# declarations put a type (or `var`) before the name.
			if lang == langCSharp {
				left = stripCSharpDeclType(left)
			}
			if isSimpleIdent(left) {
				return left, right
			}
			return "", ""
		}
	}
	return "", ""
}

// stripDeclKeyword removes a leading const/let/var from a JS assignment LHS.
func stripDeclKeyword(left string) string {
	for _, kw := range []string{"const ", "let ", "var "} {
		if strings.HasPrefix(left, kw) {
			return strings.TrimSpace(strings.TrimPrefix(left, kw))
		}
	}
	return left
}

// stripRustLetKeyword removes a leading `let ` / `let mut ` binding keyword and
// any `: Type` annotation from a Rust assignment LHS, leaving the bare binding
// name. `let x = e`, `let mut x = e`, and `let x: String = e` all yield `x`.
// A non-`let` LHS (a reassignment `x = e`) is returned with only the annotation
// stripped, so `x: T = e` still resolves to `x` (rare, but harmless).
func stripRustLetKeyword(left string) string {
	left = strings.TrimSpace(left)
	if strings.HasPrefix(left, "let ") {
		left = strings.TrimSpace(strings.TrimPrefix(left, "let "))
		if strings.HasPrefix(left, "mut ") {
			left = strings.TrimSpace(strings.TrimPrefix(left, "mut "))
		}
	}
	// Drop a `: Type` annotation on the binding (`x: String` -> `x`).
	if i := strings.IndexByte(left, ':'); i >= 0 {
		left = strings.TrimSpace(left[:i])
	}
	return left
}

// stripCSharpDeclType reduces a C# assignment LHS to its bare variable name by
// dropping a leading type (or `var`) declaration. A C# local declaration reads
// `<type> name = expr` — e.g. `var name`, `string user`, `SqlCommand cmd`,
// `List<int> xs`, `byte[] data`, `IEnumerable<string> rows`. The variable name
// is the LAST whitespace-separated token; everything before it is the type
// (possibly with generic/array brackets, already balanced in the code view).
// A single bare token (`name`) is returned unchanged — it is a plain
// reassignment, not a declaration. Best-effort and deterministic: an
// unrecognizable LHS falls through to isSimpleIdent, which rejects it safely.
func stripCSharpDeclType(left string) string {
	left = strings.TrimSpace(left)
	// Find the last top-level space (not inside <...> or [...]) — the boundary
	// between the type and the variable name.
	depth := 0
	lastSpace := -1
	for i := 0; i < len(left); i++ {
		switch left[i] {
		case '<', '[', '(':
			depth++
		case '>', ']', ')':
			if depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 {
				lastSpace = i
			}
		}
	}
	if lastSpace < 0 {
		return left // bare identifier: a plain reassignment
	}
	return strings.TrimSpace(left[lastSpace+1:])
}

// callChain is a recognized call: its normalized callee key, the code-view
// argument text (literals blanked) used to find variable reads, and the raw
// argument text (literals intact) used to count positional arguments.
type callChain struct {
	callee   string
	codeArgs string
	rawArgs  string
}

// extractCalls finds every `chain(args)` in code and returns the normalized
// callee plus both argument views. raw must be byte-aligned to code (same length
// and offsets) so argument slices line up. Nested calls are all reported.
func extractCalls(_ langKind, code, raw string) []callChain {
	var calls []callChain
	i := 0
	n := len(code)
	aligned := len(raw) == len(code)
	for i < n {
		if !isIdentStart(code[i]) {
			i++
			continue
		}
		start := i
		for i < n && (isIdentPart(code[i]) || code[i] == '.') {
			i++
		}
		chain := code[start:i]
		j := i
		for j < n && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j >= n || code[j] != '(' {
			continue // not a call, just an identifier/attribute read
		}
		codeArgs, end := balancedArgs(code, j)
		rawArgs := codeArgs
		if aligned && j < end-1 && end-1 <= len(raw) {
			// end indexes just past ')'; the args span is (j+1, end-1).
			rawArgs = raw[j+1 : end-1]
		}
		callee := normalizeCallee(chain)
		if callee != "" {
			calls = append(calls, callChain{callee: callee, codeArgs: codeArgs, rawArgs: rawArgs})
		}
		// Recurse into the argument text so NESTED calls are also captured —
		// e.g. the inner shlex.quote in os.system(shlex.quote(user)). Both views
		// stay aligned (same span slice), so nested arg counting still works.
		if codeArgs != "" {
			calls = append(calls, extractCalls(langPython, codeArgs, rawArgs)...)
		}
		i = end
	}
	return calls
}

// dottedChains returns every dotted identifier chain in code (a.b.c), whether
// or not it is called. Single bare identifiers are excluded (they are ordinary
// variable reads, already tracked); only multi-segment chains are returned,
// since those are what source ATTRIBUTES look like (request.args, req.query).
// Deterministic and deduplicated.
func dottedChains(code string) []string {
	seen := map[string]struct{}{}
	var out []string
	i := 0
	n := len(code)
	for i < n {
		if !isIdentStart(code[i]) {
			// Skip a leading '.' so we don't start mid-chain.
			i++
			continue
		}
		start := i
		for i < n && (isIdentPart(code[i]) || code[i] == '.') {
			i++
		}
		chain := code[start:i]
		if strings.Contains(chain, ".") {
			if _, dup := seen[chain]; !dup {
				seen[chain] = struct{}{}
				out = append(out, chain)
			}
		}
	}
	return out
}

// balancedArgs returns the text inside the parentheses starting at open (which
// must index a '(') and the index just past the matching ')'. Handles nested
// brackets. Literals are already blanked, so no in-string paren confusion.
func balancedArgs(code string, open int) (args string, end int) {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return code[open+1 : i], i + 1
			}
		}
	}
	return code[open+1:], len(code)
}

// normalizeCallee maps a raw dotted chain to the catalog's call key. It keeps
// the most specific suffix the catalog is likely to hold: the full chain, and —
// so that framework-prefixed chains match — progressively shorter dotted
// suffixes are what the catalog lookup will try (see suffixKeys). Here we return
// the trailing chain, dropping a leading receiver variable only when it is a
// bracket/subscript artifact. The catalog matching does suffix fallback.
func normalizeCallee(chain string) string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return ""
	}
	// A pure builtin like eval/exec/open/input has no dot.
	return chain
}

// suffixKeys returns the dotted suffixes of a call chain from longest to
// shortest, e.g. "flask.request.args.get" → ["flask.request.args.get",
// "request.args.get", "args.get", "get"]. The engine tries each against the
// catalog in order, so a framework-prefixed chain (flask.request.args.get) and
// an aliased-import chain still match the catalog's canonical suffix
// (request.args.get) without the catalog enumerating every prefix. Longest-first
// keeps the match specific.
func suffixKeys(chain string) []string {
	parts := strings.Split(chain, ".")
	out := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}
