package engine

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Reflected XSS through a Flask handler's return value.
//
// Flask serves a string a view returns as the body of a text/html response.
// So `return f"<p>{request.args['q']}</p>"` from a route is reflected XSS with
// no template involved -- and the catalog's Python XSS sinks were only
// Markup and mark_safe, so it was invisible.
//
// The sink is the return statement of a route function, added as the
// synthetic chain `flask_route.return` (like XXE and the session store: a
// return is not a call). Deliberately narrow:
//
//   - only in files that import Flask, because FastAPI uses the same
//     `@app.get(...)` decorators and serializes a returned string as JSON;
//   - only a return of a plain value -- a name, an f-string, a concatenation,
//     `str(...)`, `.format(...)`, `.join(...)`. A returned call to jsonify,
//     render_template, redirect or make_response is judged by what that call
//     is, and a returned dict or list becomes JSON.
//
// make_response and Django's HttpResponse are sinks on the BODY -- the first
// positional argument, or the first element of a (body, headers) tuple -- and
// their result is treated as neutralized for XSS, so a view that builds a
// Response and returns it is judged once, at the construction.

// FlaskReturnSinkCall is the synthetic sink chain for a route's return. It is
// exported so AGENTFLOW-002 can leave it out: returning a model's reply is
// not an action a hijacked model takes.
const FlaskReturnSinkCall = "flask_route.return"

var (
	pyImportsFlask = regexp.MustCompile(`(?m)^\s*(?:from\s+flask\b|import\s+flask\b)`)
	pyRouteDecor   = regexp.MustCompile(`^\s*@[\w.]+\.(?:route|get|post|put|patch|delete)\s*\(`)
	pyDecorator    = regexp.MustCompile(`^\s*@`)
	pyDefName      = regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)`)
	pyReturnHead   = regexp.MustCompile(`^\s*return\s+(.*)$`)
)

// plainReturnCalls are the calls a returned value may make and still be the
// body string itself.
var plainReturnCalls = map[string]bool{
	"str": true, "format": true, "join": true, "strip": true, "replace": true,
	"lower": true, "upper": true, "encode": true, "decode": true,
}

// flaskRouteFuncs returns the names of the functions decorated as Flask routes.
func flaskRouteFuncs(content []byte) map[string]bool {
	if !pyImportsFlask.Match(content) {
		return nil
	}
	out := map[string]bool{}
	route := false
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case pyRouteDecor.MatchString(line):
			route = true
		case pyDecorator.MatchString(line):
			// another decorator in the same stack keeps the flag
		case route:
			if m := pyDefName.FindStringSubmatch(line); m != nil {
				out[m[1]] = true
			}
			if strings.TrimSpace(line) != "" {
				route = false
			}
		}
	}
	return out
}

// applyFlaskReturns adds the handler-return sink to plain-value returns in
// Flask route functions.
func applyFlaskReturns(drafts []unitDraft, content []byte) {
	routes := flaskRouteFuncs(content)
	if len(routes) == 0 {
		return
	}
	lines := strings.Split(string(lexctx.MaskNonCode(lexctx.LangPython, content)), "\n")
	for i := range drafts {
		if !routes[drafts[i].funcName] {
			continue
		}
		// responses: locals whose latest assignment built a Response (or
		// JSON, a template, a redirect). Returning one is judged where it was
		// built, not again here.
		responses := map[string]bool{}
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			if st.assigns != "" && len(st.returns) == 0 {
				responses[st.assigns] = buildsResponse(st.calls)
				continue
			}
			if len(st.returns) == 0 || st.line < 1 || st.line > len(lines) {
				continue
			}
			m := pyReturnHead.FindStringSubmatch(lines[st.line-1])
			if len(m) != 2 || !plainReturn(m[1], st.calls) || responses[strings.TrimSpace(m[1])] {
				continue
			}
			st.calls = append(st.calls, FlaskReturnSinkCall)
		}
	}
}

// responseBuilders are the calls whose result is a response, not a body.
var responseBuilders = map[string]bool{
	"make_response": true, "jsonify": true, "render_template": true,
	"redirect": true, "Response": true, "HttpResponse": true,
	"send_file": true, "send_from_directory": true, "JsonResponse": true,
}

func buildsResponse(calls []string) bool {
	for _, c := range calls {
		if responseBuilders[lastDotted(c)] {
			return true
		}
	}
	return false
}

// plainReturn reports whether a returned expression is the body string
// itself: not a dict or list (JSON), and making no call that turns it into
// something else.
func plainReturn(expr string, calls []string) bool {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "{") || strings.HasPrefix(expr, "[") {
		return false
	}
	for _, c := range calls {
		if !plainReturnCalls[lastDotted(c)] {
			return false
		}
	}
	return true
}
