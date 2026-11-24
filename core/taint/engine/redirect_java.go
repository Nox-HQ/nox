package engine

import (
	"bytes"
	"regexp"
	"strings"
)

// SpringRedirectSinkCall is the synthetic call recorded for a Spring MVC
// redirect view built from a value: `return "redirect:" + url`,
// `new ModelAndView("redirect:" + url)`. A controller returning that string
// sends the browser to whatever follows the prefix, and nothing about it is a
// call the catalog could name. The catalog lists this chain as an open
// redirect sink (TAINT-007).
const SpringRedirectSinkCall = "spring_mvc.redirect_view"

// springRedirectConcat is the prefix followed by a concatenation. A fixed
// target (`"redirect:/home"`) has no `+` after the closing quote.
var springRedirectConcat = regexp.MustCompile(`"redirect:"\s*\+`)

// javaRedirectCall is a redirect call followed by its argument, unwrapping a
// URI constructor; group 1 is the first character of the argument.
var javaRedirectCall = regexp.MustCompile(`\b(?:sendRedirect|seeOther|temporaryRedirect|permanentRedirect|redirect|RedirectView)\s*\(\s*(?:(?:URI\s*\.\s*create|new\s+(?:java\.net\.)?URI|UriBuilder\s*\.\s*of|UriComponentsBuilder\s*\.\s*fromPath)\s*\(\s*)?("/[^/\\"]|"/")`)

// redirectCallees are the last segments of the Java redirect sinks.
var redirectCallees = map[string]bool{
	"sendRedirect": true, "seeOther": true, "temporaryRedirect": true,
	"permanentRedirect": true, "redirect": true, "RedirectView": true,
}

// dropFixedPathRedirects removes the redirect sink from a statement whose
// redirect target begins with a fixed path on this site -- "/items/" + id,
// URI.create("/cohorts/" + id), UriBuilder.of("/reset") -- since a value after
// a fixed path cannot send the browser to another host. A protocol-relative
// "//" or "/\\" prefix is not a fixed path.
func dropFixedPathRedirects(drafts []unitDraft, lines []string) {
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			if st.line < 1 || st.line > len(lines) || !javaRedirectCall.MatchString(lines[st.line-1]) {
				continue
			}
			kept := st.calls[:0:0]
			for _, c := range st.calls {
				if !redirectCallees[lastDotted(c)] {
					kept = append(kept, c)
				}
			}
			st.calls = kept
		}
	}
}

// applySpringRedirectViews adds the redirect sink to every statement of a
// Spring file whose text builds a redirect view name by concatenation. The
// statement's own reads decide whether the value is tainted.
func applySpringRedirectViews(drafts []unitDraft, content []byte) {
	lines := strings.Split(string(content), "\n")
	dropFixedPathRedirects(drafts, lines)
	if !bytes.Contains(content, []byte("springframework")) || !bytes.Contains(content, []byte(`"redirect:"`)) {
		return
	}
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			if st.line < 1 || st.line > len(lines) || !springRedirectConcat.MatchString(lines[st.line-1]) {
				continue
			}
			st.calls = append(st.calls, SpringRedirectSinkCall)
		}
	}
}
