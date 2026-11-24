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

// applySpringRedirectViews adds the redirect sink to every statement of a
// Spring file whose text builds a redirect view name by concatenation. The
// statement's own reads decide whether the value is tainted.
func applySpringRedirectViews(drafts []unitDraft, content []byte) {
	if !bytes.Contains(content, []byte("springframework")) || !bytes.Contains(content, []byte(`"redirect:"`)) {
		return
	}
	lines := strings.Split(string(content), "\n")
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
