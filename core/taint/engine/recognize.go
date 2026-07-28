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
	langCPP
	langPerl
	langScala
	langKotlin
	langShell
	langPowerShell
	langSwift
	langLua
	langClojure
	langElixir
	langDart
	langGroovy
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
			// C/C++ declarations put a type before the name, possibly with
			// pointer/reference sigils (`char *user`, `const std::string& s`) or
			// `auto`. Strip the type so the bare declared name is the LHS.
			if lang == langCPP {
				left = stripCPPDeclType(left)
			}
			// Perl `my` / `our` / `local` binding keywords precede the name (the `$`
			// sigil is already stripped by normalization, leaving `my  x`). A list
			// assignment `my ($a, $b) = @_` is not a simple-ident LHS and is left to
			// fail isSimpleIdent below (we do not track list-destructuring taint).
			if lang == langPerl {
				left = stripPerlDeclKeyword(left)
			}
			// Scala `val` / `var` binding keywords, plus a trailing `: Type`
			// annotation on the binding (`val x: String = ...`).
			if lang == langScala {
				left = stripScalaValKeyword(left)
			}
			// Kotlin `val`/`var` binding keywords, plus a trailing `: Type`
			// annotation on the binding (`val x: String = ...`).
			if lang == langKotlin {
				left = stripKotlinDeclType(left)
			}
			// Swift `let` / `var` binding keywords, plus a trailing `: Type`
			// annotation on the binding (`let x: String = ...`).
			if lang == langSwift {
				left = stripSwiftLetKeyword(left)
			}
			// Lua `local` binding keyword precedes the name (`local x = e`). A plain
			// reassignment (`x = e`, no keyword) is returned unchanged. A multiple
			// assignment `local a, b = f()` is not a simple-ident LHS and is left to
			// fail isSimpleIdent below (we do not track list-destructuring taint).
			if lang == langLua {
				left = stripLuaLocalKeyword(left)
			}
			// Dart declarations use a `var`/`final`/`const` keyword or a leading
			// type (`String x = ...`, `final String x = ...`). Strip them so the
			// bare declared name is the LHS.
			if lang == langDart {
				left = stripDartDeclType(left)
			}
			// Groovy declarations use `def name`, a bare typed `Type name`, or a
			// plain reassignment `name`. Strip the `def`/type so the bare declared
			// name is the LHS.
			if lang == langGroovy {
				left = stripGroovyDeclType(left)
			}
			// Ruby's shared-state sigils (`@ivar`, `@@cvar`, `$global`) are part
			// of the NAME, not the expression. Strip them so the binding target is
			// the bare name the read side already produces.
			if lang == langRuby {
				left = stripRubyStateSigil(left)
			}
			if isSimpleIdent(left) {
				return left, right
			}
			// An assignment to a member FIELD (`task.arguments = [...]`) binds no
			// bare name, so the tainted value never associated with the object and
			// a later bare `task.launch()` carried nothing to match. Bind the
			// RECEIVER: taint on any field is treated as taint on the object.
			if receiverTaintLangs[lang] {
				if root, ok := dottedAssignRoot(left); ok {
					return root, right
				}
			}
			// An assignment to a container ELEMENT (`$args{cmd} = $ENV{CMD}`)
			// binds no bare name, so the taint was lost at the store and the
			// later read of the element looked clean. Bind the CONTAINER.
			if containerTaintLangs[lang] {
				if root, ok := containerAssignRoot(left); ok {
					return root, right
				}
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

// stripPerlDeclKeyword removes a leading `my` / `our` / `local` binding keyword
// from a Perl assignment LHS, leaving the bare declared name. After sigil
// normalization the LHS reads `my  cmd` (sigil blanked to a space), so the
// keyword and any surrounding whitespace are trimmed. A plain reassignment
// (`cmd = e`, no keyword) is returned unchanged.
func stripPerlDeclKeyword(left string) string {
	left = strings.TrimSpace(left)
	for _, kw := range []string{"my", "our", "local"} {
		if left == kw {
			return ""
		}
		if strings.HasPrefix(left, kw+" ") || strings.HasPrefix(left, kw+"\t") {
			return strings.TrimSpace(left[len(kw):])
		}
	}
	return left
}

// stripLuaLocalKeyword removes a leading `local ` binding keyword from a Lua
// assignment LHS, leaving the bare declared name. `local x = e` yields `x`; a
// plain reassignment `x = e` is returned unchanged.
func stripLuaLocalKeyword(left string) string {
	left = strings.TrimSpace(left)
	if left == "local" {
		return ""
	}
	if strings.HasPrefix(left, "local ") || strings.HasPrefix(left, "local\t") {
		return strings.TrimSpace(left[len("local"):])
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

var receiverTaintLangs = map[langKind]bool{
	langSwift: true,
	langCPP:   true,
	langDart:  true,
}

func dottedAssignRoot(left string) (string, bool) {
	if left == "" || !strings.Contains(left, ".") {
		return "", false
	}
	segs := strings.Split(left, ".")
	for _, seg := range segs {
		if !isBareIdent(strings.TrimSpace(seg)) {
			return "", false
		}
	}
	root := strings.TrimSpace(segs[0])
	if isKeyword(root) {
		return "", false
	}
	return root, true
}

// containerTaintLangs are the languages where an assignment to a container
// ELEMENT is modeled as tainting the whole container. Like receiver taint this
// is field-INSENSITIVE — a taint on any element taints every read of the
// container — so it can only widen taint and is enabled per language as a
// corpus demands it.
var containerTaintLangs = map[langKind]bool{
	langPerl: true,
}

// containerAssignRoot returns the container name of an element-assignment target
// (`args{cmd}` -> `args`, `list[0]` -> `list`). The subscript must be a single
// balanced `{...}`/`[...]` that ends the target, so a nested or dotted target
// yields ok=false rather than a misattributed binding.
func containerAssignRoot(left string) (string, bool) {
	i := 0
	for i < len(left) && isIdentPart(left[i]) {
		i++
	}
	if i == 0 || i >= len(left) {
		return "", false
	}
	open := left[i]
	if open != '{' && open != '[' {
		return "", false
	}
	closing := byte('}')
	if open == '[' {
		closing = ']'
	}
	depth := 0
	for j := i; j < len(left); j++ {
		switch left[j] {
		case open:
			depth++
		case closing:
			depth--
			if depth == 0 {
				// The subscript must end the target.
				if j != len(left)-1 {
					return "", false
				}
				root := left[:i]
				if isKeyword(root) || !isBareIdent(root) {
					return "", false
				}
				return root, true
			}
		}
	}
	return "", false
}

// stripRubyStateSigil removes a leading `@@`, `@` or `$` from a Ruby assignment
// target so `@cmd` binds the name `cmd` — which is what freeIdentifiers already
// produces on the read side, so the two agree.
func stripRubyStateSigil(left string) string {
	switch {
	case strings.HasPrefix(left, "@@"):
		return left[2:]
	case strings.HasPrefix(left, "@"), strings.HasPrefix(left, "$"):
		return left[1:]
	}
	return left
}

// rubyStateSigilName returns the bare name of a Ruby shared-state assignment
// target (`@cmd = ...` -> `cmd`), or "" when the line does not assign one.
func rubyStateSigilName(code string) string {
	t := strings.TrimLeft(code, " \t")
	if t == "" || (t[0] != '@' && t[0] != '$') {
		return ""
	}
	lhs, _ := splitAssignment(langRuby, t)
	if lhs == "" || !isSimpleIdent(lhs) {
		return ""
	}
	return lhs
}
