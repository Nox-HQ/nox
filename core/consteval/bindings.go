package consteval

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// This file carries constant resolution for every language that is not Go.
//
// # Why it is not a parser
//
// nox is a language-agnostic scanner, and a capability that answers for one
// language is not a capability — it is a Go feature with a general-sounding
// name. But nox also cannot carry a parser for twenty-five languages, and the
// Go path here exists precisely because `go/ast` is free to a program written
// in Go.
//
// So this layer answers the same question from what `core/lexctx` already
// establishes: which bytes are code, which are string, which are comment. That
// is enough to see a binding form and to count how many times a name is bound,
// and those two facts together are what "constant" means operationally — the
// name was declared immutable, and nothing in the file rebinds it.
//
// This mirrors the taint engine's split exactly: `extract_go.go` is AST-precise
// because Go is free, and every other language is served by a recognizer.
//
// # Two bases, and they are not equally strong
//
// Some languages have a keyword that makes a binding immutable — `const`,
// `final`, `val`, `let`. Reading one is a fact about the program.
//
// Python and Ruby have no such keyword for local names; the constant is a
// convention (ALL_CAPS, or a capitalized Ruby constant). Establishing one is a
// weaker claim, and it is reported as a weaker claim: BasisSingleBinding, which
// the caller records as heuristic evidence rather than static.
//
// Conflating them would put a keyword's certainty behind a naming convention,
// and this package's whole job is to be exact about which questions were
// actually answered.

// Basis records HOW constancy was established, so a caller can record evidence
// of the right strength rather than flattening two different facts into one.
type Basis string

const (
	// BasisNone — nothing was established.
	BasisNone Basis = ""
	// BasisDeclared — the language has an immutable-binding keyword and the
	// name carries it. A fact about the program.
	BasisDeclared Basis = "declared"
	// BasisSingleBinding — the language has no such keyword, and the name is
	// bound exactly once in the file, to a literal, under the language's
	// constant naming convention. Weaker: nothing prevents a rebinding this
	// file cannot see.
	BasisSingleBinding Basis = "single-binding"
)

// bindingSyntax describes how one language declares an immutable name.
type bindingSyntax struct {
	// keywords introduce an immutable binding. Empty means the language has
	// none and constancy rests on convention plus single binding.
	keywords []string
	// conventional reports that a name must also match the language's constant
	// naming convention, which is the only signal available without a keyword.
	conventional bool
}

// syntax is the closed table of languages this layer can answer for.
//
// A language absent from it answers UNDETERMINED, never "not constant" — the
// difference between "nox has no evaluator here" and "this value varies", which
// callers must not conflate because a refutation drops a finding.
var syntax = map[lexctx.Lang]bindingSyntax{
	// Keyword languages: the declaration itself carries immutability.
	lexctx.LangJavaScript: {keywords: []string{"const"}},
	lexctx.LangJava:       {keywords: []string{"final"}},
	lexctx.LangCSharp:     {keywords: []string{"const", "readonly"}},
	lexctx.LangRust:       {keywords: []string{"const", "static"}},
	lexctx.LangKotlin:     {keywords: []string{"val"}},
	lexctx.LangSwift:      {keywords: []string{"let"}},
	lexctx.LangScala:      {keywords: []string{"val"}},
	lexctx.LangPHP:        {keywords: []string{"const"}},
	lexctx.LangDart:       {keywords: []string{"const", "final"}},
	lexctx.LangGroovy:     {keywords: []string{"final"}},
	lexctx.LangCPP:        {keywords: []string{"const", "constexpr"}},
	lexctx.LangObjC:       {keywords: []string{"const"}},

	// Convention languages: no keyword binds a local name immutably, so a name
	// qualifies only by being bound once, to a literal, under the convention.
	lexctx.LangPython: {conventional: true},
	lexctx.LangRuby:   {conventional: true},
}

// identifier matches a name in the languages above. Deliberately conservative:
// it does not accept `$`, `@` or `-`, so a PHP variable, a Ruby instance
// variable and a Lisp-cased name are all simply not resolved.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// literalRHS matches a right-hand side that is a bare literal: a quoted string
// (already collapsed to a placeholder by the caller), a number, or a boolean.
//
// Anything else — a call, a concatenation with a name, an interpolation — is
// not accepted, because the question is whether the value can vary and only a
// literal answers it without further analysis.
var literalRHS = regexp.MustCompile(`^(?:` + strLiteralPlaceholder + `|[+-]?[0-9][0-9_.xXa-fA-F]*|true|false|True|False|nil|None|null)$`)

// strLiteralPlaceholder stands in for a string region that lexctx identified.
// Using a placeholder rather than matching quotes means escapes, raw strings,
// heredocs and interpolation delimiters never have to be re-parsed here — the
// lexer already decided where the string was.
const strLiteralPlaceholder = "\x00STR\x00"

// supportedByBindings reports whether the recognizer covers a language.
func supportedByBindings(lang lexctx.Lang) bool {
	_, ok := syntax[lang]
	return ok
}

// constantBindings returns the names this file binds immutably, and the basis.
//
// The single-binding rule applies to EVERY language, keyword or not. A `const`
// shadowed by a later assignment in the same file is not a constant this
// resolver will vouch for, and counting is the only way to see that without
// scope analysis. Over-counting costs a finding that stays reported;
// under-counting would drop one.
func constantBindings(lang lexctx.Lang, content []byte) (map[string]Basis, bool) {
	syn, ok := syntax[lang]
	if !ok {
		return nil, false
	}
	masked := maskNonCode(lang, content)

	bindings := make(map[string]Basis)
	counts := make(map[string]int)

	for _, line := range strings.Split(masked, "\n") {
		name, rhs, kw, ok := splitBinding(line, syn.keywords)
		if !ok {
			continue
		}
		counts[name]++
		if !literalRHS.MatchString(trimStatementEnd(rhs)) {
			// Bound to something that is not a literal. The name is still
			// BOUND, so the count stands and will disqualify it below.
			continue
		}
		switch {
		case kw != "":
			bindings[name] = BasisDeclared
		case syn.conventional && isConventionalConstantName(lang, name):
			bindings[name] = BasisSingleBinding
		}
	}

	// A name bound more than once is not constant, whatever it was declared as.
	for name, n := range counts {
		if n > 1 {
			delete(bindings, name)
		}
	}
	return bindings, true
}

// splitBinding pulls `[keyword] NAME = RHS` out of one masked line.
//
// It requires the `=` to be a plain assignment: `==`, `!=`, `<=`, `>=`, `=>`
// and `:=`-style comparisons are rejected, because a comparison binds nothing
// and reading one as a binding would let an `if NAME == "x"` disqualify the
// real declaration above it.
func splitBinding(line string, keywords []string) (name, rhs, keyword string, ok bool) {
	eq := indexPlainAssign(line)
	if eq < 0 {
		return "", "", "", false
	}
	lhs := strings.TrimSpace(line[:eq])
	rhs = line[eq+1:]

	fields := strings.Fields(lhs)
	if len(fields) == 0 {
		return "", "", "", false
	}
	// The name is the last token: `const X`, `static final String X`,
	// `const NAME: &str`, or a bare `NAME`.
	name = strings.TrimSuffix(fields[len(fields)-1], ":")
	// A typed declaration puts the type between the name and the `=`
	// (`const NAME: &str = …`); the colon was trimmed, but Rust and Kotlin
	// write the type after it, so take the token before a type annotation.
	if len(fields) >= 2 && strings.HasSuffix(fields[len(fields)-2], ":") {
		name = strings.TrimSuffix(fields[len(fields)-2], ":")
	}
	if !identifier.MatchString(name) {
		return "", "", "", false
	}
	for _, kw := range keywords {
		for _, f := range fields[:max(len(fields)-1, 0)] {
			if f == kw {
				keyword = kw
			}
		}
	}
	return name, rhs, keyword, true
}

// trimStatementEnd strips the punctuation a statement ends with, so a binding
// reads the same in a language with terminators and one without.
//
// Without it the recognizer answered for Python and Ruby and silently failed
// for every brace language, because `const P = "x";` leaves a `;` on the
// right-hand side and no literal ends in a semicolon.
func trimStatementEnd(rhs string) string {
	return strings.TrimRight(strings.TrimSpace(rhs), ";, \t")
}

// indexPlainAssign returns the index of a single `=` that assigns, or -1.
func indexPlainAssign(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// `==`, `=>`; and `!=`, `<=`, `>=`, `+=`, `:=` and friends.
		if i+1 < len(line) && (line[i+1] == '=' || line[i+1] == '>') {
			return -1
		}
		if i > 0 && strings.ContainsRune("=!<>+-*/%&|^:", rune(line[i-1])) {
			return -1
		}
		return i
	}
	return -1
}

// isConventionalConstantName applies the language's constant naming rule.
//
// Python: PEP 8 says module-level constants are ALL_CAPS. Ruby: a constant is
// any name beginning with a capital. The convention is doing real work here —
// it is the only signal these languages give — and requiring it is also what
// keeps a function PARAMETER from being read as a constant, since parameters
// are not written this way.
func isConventionalConstantName(lang lexctx.Lang, name string) bool {
	if name == "" {
		return false
	}
	switch lang {
	case lexctx.LangPython:
		if strings.ToUpper(name) != name {
			return false
		}
		// A name of only underscores and digits is not a constant name.
		return strings.IndexFunc(name, func(r rune) bool {
			return r >= 'A' && r <= 'Z'
		}) >= 0
	case lexctx.LangRuby:
		c := name[0]
		return c >= 'A' && c <= 'Z'
	default:
		return false
	}
}

// maskNonCode replaces every comment byte with a space and every string region
// with a single placeholder token, keeping byte offsets stable enough for
// line-oriented scanning while removing everything that is not program text.
//
// Masking rather than deleting is what stops a trigger word inside a comment
// from being read as code — the defect that produced four self-caused waivers
// in this repository — and what lets literalRHS recognise a string without
// re-deriving where the string ended.
func maskNonCode(lang lexctx.Lang, content []byte) string {
	regions := lexctx.Classify(lang, content)
	var b strings.Builder
	b.Grow(len(content))

	prev := 0
	for _, r := range regions {
		if r.Start > prev {
			b.Write(content[prev:r.Start])
		}
		seg := content[r.Start:min(r.End, len(content))]
		switch r.Kind {
		case lexctx.KindCode:
			b.Write(seg)
		case lexctx.KindString:
			b.WriteString(strLiteralPlaceholder)
			// Keep newlines so line numbers and line splitting stay aligned
			// for multi-line strings.
			b.WriteString(strings.Repeat("\n", countNewlines(seg)))
		default:
			// Comments become blanks, preserving line structure.
			b.WriteString(strings.Repeat("\n", countNewlines(seg)))
		}
		prev = r.End
	}
	if prev < len(content) {
		b.Write(content[prev:])
	}
	return b.String()
}

func countNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

// callArgumentsAreConstantLexically answers the call question for a language
// with no parser here.
//
// It finds the call's parentheses in CODE regions — so a `(` inside a string or
// a comment never opens a call — splits the arguments on top-level commas, and
// asks the same question of each: is this a literal, or a name this file binds
// immutably?
//
// Every shape it does not recognise returns UNDETERMINED. That is the whole
// safety argument: the caller refutes on this answer, refuting drops a finding,
// and a recognizer that guessed would hide real issues in twenty-four
// languages at once.
func callArgumentsAreConstantLexically(lang lexctx.Lang, content []byte, offset int) Result {
	bindings, ok := constantBindings(lang, content)
	if !ok {
		return undetermined("no constant evaluator for this language")
	}

	regions := lexctx.Classify(lang, content)
	open := nextCodeByte(regions, content, offset, '(')
	if open < 0 {
		return undetermined("no call opener after the match")
	}
	closing := matchingParen(regions, content, open)
	if closing < 0 {
		return undetermined("call parentheses do not close within the scan window")
	}

	args := splitArgs(regions, content, open+1, closing)
	if len(args) == 0 {
		return Result{Constant: true, Determined: true, Basis: BasisDeclared}
	}

	weakest := BasisDeclared
	for _, a := range args {
		r := argumentIsConstant(regions, content, a[0], a[1], bindings)
		if !r.Determined || !r.Constant {
			return r
		}
		if r.Basis == BasisSingleBinding {
			// The call is only as strong as its weakest argument.
			weakest = BasisSingleBinding
		}
	}
	return Result{Constant: true, Determined: true, Basis: weakest}
}

// argumentIsConstant decides one argument span.
func argumentIsConstant(regions []lexctx.Region, content []byte, from, to int, bindings map[string]Basis) Result {
	// A span that is entirely one string region is a literal.
	text := strings.TrimSpace(string(content[from:min(to, len(content))]))
	if text == "" {
		return undetermined("empty argument")
	}
	if spanIsWhollyString(regions, content, from, to) {
		return Result{Constant: true, Determined: true, Basis: BasisDeclared}
	}
	if literalRHS.MatchString(text) {
		return Result{Constant: true, Determined: true, Basis: BasisDeclared}
	}
	if identifier.MatchString(text) {
		if basis, ok := bindings[text]; ok {
			return Result{Constant: true, Determined: true, Basis: basis}
		}
		return undetermined("name " + text + " does not resolve to a constant in this file")
	}
	return undetermined("argument is not a literal or a constant name")
}

// spanIsWhollyString reports whether every non-space byte of the span lies in a
// string region — the lexer's answer to "is this argument a literal?".
func spanIsWhollyString(regions []lexctx.Region, content []byte, from, to int) bool {
	saw := false
	for i := from; i < to && i < len(content); i++ {
		if content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r' {
			continue
		}
		if lexctx.KindAt(regions, i) != lexctx.KindString {
			return false
		}
		saw = true
	}
	return saw
}

// nextCodeByte returns the offset of the next b at or after from that lies in a
// code region, bounded by maxCallScan.
func nextCodeByte(regions []lexctx.Region, content []byte, from int, b byte) int {
	for i := max(from, 0); i < min(from+maxCallScan, len(content)); i++ {
		if content[i] == b && lexctx.KindAt(regions, i) == lexctx.KindCode {
			return i
		}
	}
	return -1
}

// matchingParen returns the offset of the ')' closing the '(' at open, counting
// only parentheses in code regions so a ')' inside a message string does not
// close the call.
func matchingParen(regions []lexctx.Region, content []byte, open int) int {
	depth := 0
	for i := open; i < min(open+maxCallScan, len(content)); i++ {
		if lexctx.KindAt(regions, i) != lexctx.KindCode {
			continue
		}
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitArgs returns the [start,end) spans of the top-level arguments between
// from and to, splitting on commas that sit in code at depth zero.
func splitArgs(regions []lexctx.Region, content []byte, from, to int) [][2]int {
	var out [][2]int
	depth := 0
	start := from
	for i := from; i < to && i < len(content); i++ {
		if lexctx.KindAt(regions, i) != lexctx.KindCode {
			continue
		}
		switch content[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, [2]int{start, i})
				start = i + 1
			}
		}
	}
	if start < to {
		out = append(out, [2]int{start, to})
	}
	return out
}

// maxCallScan bounds how far the recognizer will look for a call's closing
// parenthesis. A call that runs longer than this is not one this layer will
// vouch for, and the bound also keeps a pathological file from making the
// scanner the expensive part of a scan.
const maxCallScan = 4096
