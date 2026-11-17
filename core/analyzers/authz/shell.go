package authz

import (
	"regexp"
	"strings"
)

// SPA shell routes.
//
// A single-page app is served by one HTML file the server returns for every
// URL under the app (`app.get('*', (req, res) => res.sendFile('index.html'))`,
// Rails' `get '/app/*params', to: 'dashboard#index'`), and the client router
// takes it from there. The page is the same for every caller and carries no
// record: what the user sees is fetched afterwards from API routes, which are
// the routes that need authentication, and which this reader reads on their
// own. So a route that serves the shell is not "a route that reads or changes
// something an anonymous caller should not reach", whatever its path looks
// like (`/admin/*`, `/accounts/:id/settings`).
//
// What it states, and no more: an Express-style GET handler is the shell when
// its whole body is one sendFile of an .html file whose path is written
// without anything from the request. A handler that does anything else (reads
// the request, loads data, renders a template with a model), a sendFile of a
// path built from `req`, and any method but GET are not the shell. The Rails
// rule is in rails.go, where the action is read.

// jsShellHandlerRe matches a handler that is exactly `res.sendFile(<arg>)`, as
// an arrow function, a function expression or a block body.
var jsShellHandlerRe = regexp.MustCompile(`(?s)^(?:async\s*)?(?:function\s*\w*\s*)?\(\s*\w*\s*(?:,\s*\w+\s*)?(?:,\s*\w+\s*)?\)\s*(?:=>)?\s*\{?\s*(?:return\s+)?\w+\s*\.\s*sendFile\s*\((.*)\)\s*;?\s*\}?$`)

var (
	jsHTMLFileRe    = regexp.MustCompile(`\.html?['"` + "`" + `]`)
	jsFromRequestRe = regexp.MustCompile(`\b(?:req|request|ctx|params|query|body)\b`)
)

// jsShellHandler reports whether a route's handler serves a fixed HTML file.
func jsShellHandler(method, handler string, known bool) bool {
	if !known || method != "GET" {
		return false
	}
	h := strings.Join(strings.Fields(handler), " ")
	m := jsShellHandlerRe.FindStringSubmatch(h)
	if m == nil {
		return false
	}
	return jsHTMLFileRe.MatchString(m[1]) && !jsFromRequestRe.MatchString(m[1])
}
