package engine

import "strings"

// scopeFunctions are the receiver-scoping higher-order functions whose lambda
// parameter IS the value the function was applied to:
//
//	request.getParameter("cmd").let { cmd -> exec(cmd) }   // Kotlin
//	request.getParameter("cmd").with { c -> c.execute() }  // Groovy
//
// In both, `cmd`/`c` is an ALIAS of the receiver, so taint on the receiver is
// taint on the parameter. Without modeling that, a source piped straight into
// the lambda is never bound to a name and the sink inside sees a clean value.
//
// Deliberately limited to the pure receiver-scoping functions. The COLLECTION
// ones (`each`, `collect`, `find`, `map`) bind an ELEMENT rather than the
// receiver; propagating container taint to elements is a broader decision than
// this aliasing, so they are left out rather than guessed at.
//
// `run`/`apply` bind the receiver to `this` instead of a named parameter and are
// likewise out of scope here.
var scopeFunctions = map[string]bool{
	// Kotlin
	"let": true, "also": true, "takeIf": true, "takeUnless": true,
	// Groovy
	"with": true, "tap": true, "identity": true,
}

// scopeFunctionBinding recognizes `RECEIVER.scopefn { PARAM ->` (or an implicit
// `it` when the lambda declares no parameter) and returns a synthetic
// `PARAM = RECEIVER` logical line. Feeding that to recognizeStatement binds the
// parameter to the receiver's taint using the ordinary assignment machinery, so
// statements inside the lambda body — which arrive on later lines — resolve the
// parameter as tainted.
//
// Returns ok=false for anything that is not this exact shape, including a typed
// or destructuring parameter list, which is not a simple alias.
func scopeFunctionBinding(ll logicalLine) (logicalLine, bool) {
	code := ll.code
	brace := strings.IndexByte(code, '{')
	if brace < 0 {
		return logicalLine{}, false
	}
	head := strings.TrimRight(code[:brace], " \t")
	dot := strings.LastIndexByte(head, '.')
	if dot < 0 || !scopeFunctions[head[dot+1:]] {
		return logicalLine{}, false
	}
	recv := strings.TrimSpace(head[:dot])
	if recv == "" {
		return logicalLine{}, false
	}
	// The lambda parameter: `{ cmd ->` names it, a bare `{` implies `it`. A
	// non-identifier before the arrow (a typed or destructuring parameter) is not
	// a plain alias, so it is skipped rather than guessed at.
	param := "it"
	if arrow := strings.Index(code[brace+1:], "->"); arrow >= 0 {
		cand := strings.TrimSpace(code[brace+1 : brace+1+arrow])
		if !isBareIdent(cand) {
			return logicalLine{}, false
		}
		param = cand
	}
	rawRecv := recv
	if len(ll.raw) == len(code) && dot <= len(ll.raw) {
		rawRecv = strings.TrimSpace(ll.raw[:dot])
	}
	return logicalLine{
		line: ll.line,
		code: param + " = " + recv,
		raw:  param + " = " + rawRecv,
	}, true
}
