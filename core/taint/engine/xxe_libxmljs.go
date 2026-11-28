package engine

import (
	"regexp"
	"strings"
)

// XML external entity resolution (XXE, CWE-611) in Node through libxmljs.
//
// libxmljs and libxmljs2 do not substitute entities by default; the `noent`
// option turns substitution on, and with it external entities are read. So
// the sink is a parse call given that option, not every parse call:
//
//	libxmljs.parseXmlString(body, { noent: true })   // XXE
//	libxmljs.parseXmlString(body)                    // safe
//
// The option object is read where it is written: in the call's second
// argument, or, when that argument is a bare name, in an object literal
// assigned to that name in the same file. A call that passes `noent: true`
// gains the synthetic chain xxeNoentSinkCall, which the catalog lists as the
// sink, with the call's argument record, so the engine judges the document
// (the first argument) as for every other sink. Additions only.
//
// Known limits: options built up property by property, or passed through a
// helper.

// xxeNoentSinkCall is the synthetic chain the catalog lists as the sink.
const xxeNoentSinkCall = "xxe_noent_parser.parse"

var (
	jsNoentTrue = regexp.MustCompile(`\bnoent\s*:\s*true\b`)
	// `name = { ... }`: the object literal a name is assigned, up to its
	// first closing brace (option objects are flat).
	jsObjectAssign = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*=\s*\{([^}]*)\}`)
	jsIdentifier   = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
)

// libxmljsParseCall reports whether a call chain is libxmljs's or libxmljs2's
// document parser.
func libxmljsParseCall(chain string) bool {
	head, method, ok := strings.Cut(chain, ".")
	if !ok || (head != "libxmljs" && head != "libxmljs2") {
		return false
	}
	return method == "parseXmlString" || method == "parseXml"
}

// applyLibxmljsNoent adds the XXE sink chain to every libxmljs parse call in
// the file that passes `noent: true`.
func applyLibxmljsNoent(drafts []unitDraft, content []byte) {
	if !jsNoentTrue.Match(content) {
		return
	}
	noentNames := map[string]bool{}
	for _, m := range jsObjectAssign.FindAllSubmatch(content, -1) {
		if jsNoentTrue.Match(m[2]) {
			noentNames[string(m[1])] = true
		}
	}
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			for _, call := range st.calls {
				if !libxmljsParseCall(call) {
					continue
				}
				info, ok := st.sinkArgs[call]
				if !ok || len(info.positionalArgs) < 2 {
					continue
				}
				if !passesNoent(strings.TrimSpace(info.positionalArgs[1]), noentNames) {
					continue
				}
				st.calls = append(st.calls, xxeNoentSinkCall)
				st.sinkArgs[xxeNoentSinkCall] = info
				break
			}
		}
	}
}

// passesNoent reports whether an options argument sets noent: as an object
// literal written in the call, or as a name assigned one that does.
func passesNoent(opts string, noentNames map[string]bool) bool {
	if jsNoentTrue.MatchString(opts) {
		return true
	}
	return jsIdentifier.MatchString(opts) && noentNames[opts]
}
