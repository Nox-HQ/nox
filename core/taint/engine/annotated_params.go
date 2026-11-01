package engine

import (
	"slices"
	"strings"
)

// JVM web frameworks bind the request into a handler's parameters by
// annotation (Spring's @RequestParam, JAX-RS's @QueryParam, ...). Such a
// parameter is as untrusted as request.getParameter(...), but its NAME is
// arbitrary, so the catalog cannot list it: the catalog lists one sentinel
// call per kind, and the extractor binds each such parameter from its sentinel
// at method entry (seedRequestBoundParams). An unannotated parameter is NOT promoted: a method argument may
// be a trusted, locally derived value, and tainting every parameter would
// over-report.
const (
	requestBoundQuery  = "RequestBoundQuery"
	requestBoundHeader = "RequestBoundHeader"
	requestBoundBody   = "RequestBoundBody"
)

// requestBindingAnnotations maps an annotation's simple name to the sentinel
// for the part of the request it binds. Spring MVC/WebFlux, JAX-RS (javax and
// jakarta), Micronaut and Quarkus REST.
var requestBindingAnnotations = map[string]string{
	// Spring
	"RequestParam":   requestBoundQuery,
	"PathVariable":   requestBoundQuery,
	"MatrixVariable": requestBoundQuery,
	"RequestHeader":  requestBoundHeader,
	"CookieValue":    requestBoundHeader,
	"RequestBody":    requestBoundBody,
	"RequestPart":    requestBoundBody,
	"ModelAttribute": requestBoundBody,
	// JAX-RS
	"QueryParam":  requestBoundQuery,
	"PathParam":   requestBoundQuery,
	"MatrixParam": requestBoundQuery,
	"FormParam":   requestBoundBody,
	"BeanParam":   requestBoundBody,
	"HeaderParam": requestBoundHeader,
	"CookieParam": requestBoundHeader,
	// Micronaut
	"QueryValue": requestBoundQuery,
	"Body":       requestBoundBody,
	"Header":     requestBoundHeader,
	// Quarkus REST
	"RestQuery":  requestBoundQuery,
	"RestPath":   requestBoundQuery,
	"RestForm":   requestBoundBody,
	"RestHeader": requestBoundHeader,
	"RestCookie": requestBoundHeader,
}

// leadingAnnotations splits the annotations off the front of a parameter slot:
// `@RequestParam("h") final String host` gives ["RequestParam"] and
// `final String host`. A qualified name (`@org.springframework...RequestParam`)
// yields its simple name; an annotation's argument list is skipped whole.
func leadingAnnotations(slot string) (names []string, rest string) {
	s := strings.TrimSpace(slot)
	for strings.HasPrefix(s, "@") {
		i := 1
		for i < len(s) && (isIdentByte(s[i]) || s[i] == '.') {
			i++
		}
		qualified := s[1:i]
		if dot := strings.LastIndexByte(qualified, '.'); dot >= 0 {
			qualified = qualified[dot+1:]
		}
		names = append(names, qualified)
		s = strings.TrimSpace(s[i:])
		if strings.HasPrefix(s, "(") {
			if end := matchParen(s, 0); end >= 0 {
				s = strings.TrimSpace(s[end+1:])
			} else {
				return names, s
			}
		}
	}
	return names, s
}

// requestBinding returns the sentinel for a slot's request-binding annotation,
// or "" when it carries none.
func requestBinding(annotations []string) string {
	for _, a := range annotations {
		if k, ok := requestBindingAnnotations[a]; ok {
			return k
		}
	}
	return ""
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// seedRequestBoundParams binds each request-bound parameter from its source
// at method entry: a synthetic `host = RequestBoundQuery()` on the header line,
// ahead of the body. The parameter is then tainted like any variable assigned
// from a source, whether the body passes it straight to a sink, assigns it on,
// or sanitizes it first. Seeded in name order, so output never depends on map
// iteration.
func seedRequestBoundParams(u *unitDraft) {
	if len(u.requestBound) == 0 {
		return
	}
	names := make([]string, 0, len(u.requestBound))
	for n := range u.requestBound {
		names = append(names, n)
	}
	slices.Sort(names)
	seeds := make([]stmtDraft, 0, len(names))
	for _, n := range names {
		sentinel := u.requestBound[n]
		seeds = append(seeds, stmtDraft{line: u.headerLine, assigns: n, calls: []string{sentinel}, chains: []string{sentinel}})
	}
	u.stmts = append(seeds, u.stmts...)
}

// requestBoundParams maps each request-bound parameter of a parameter list to
// its sentinel. nameOf extracts the declared name from a slot whose
// annotations are already removed; split is the language's top-level comma
// splitter.
func requestBoundParams(inner string, split func(string) []string, nameOf func(string) string) map[string]string {
	var out map[string]string
	for _, slot := range split(inner) {
		anns, rest := leadingAnnotations(slot)
		k := requestBinding(anns)
		if k == "" {
			continue
		}
		if name := nameOf(rest); isSimpleIdent(name) {
			if out == nil {
				out = map[string]string{}
			}
			out[name] = k
		}
	}
	return out
}

// headerParamList returns the text inside a method header's parameter
// parentheses: the first `(` and its match.
func headerParamList(header string) string {
	open := strings.IndexByte(header, '(')
	if open < 0 {
		return ""
	}
	end := matchParen(header, open)
	if end < 0 {
		return ""
	}
	return header[open+1 : end]
}
