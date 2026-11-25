package errleak

import (
	"regexp"
	"strings"
)

var (
	// pyExceptRe: except Types as name: (a bare except, or one without a
	// name, can still format the traceback).
	pyExceptRe = regexp.MustCompile(`(?m)^([ \t]*)except\b\s*([^\n:]*?)(?:\s+as\s+([A-Za-z_]\w*))?\s*:`)
	// pyErrorHandlerRe: a Flask or FastAPI error handler; its exception is
	// the last parameter, and what it returns is the response.
	pyErrorHandlerRe = regexp.MustCompile(`(?m)^([ \t]*)@[\w.]+\.(?:errorhandler|app_errorhandler|exception_handler)\s*\(([^)]*)\)\s*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)`)

	// pyGenericRe: an exception type whose message nobody wrote for a user.
	pyGenericRe = regexp.MustCompile(`^\(?\s*(?:Exception|BaseException)\b|\b(?:sqlite3|psycopg2?|pymysql|MySQLdb|mysql\.connector|cx_Oracle|pymongo)\.\w+|\b\w*(?:SQLAlchemy|Database|Operational|Integrity|Programming|DB|Driver|Interface)Error\b|\b(?:OSError|IOError|RuntimeError)\b`)

	// pyResponseRe: a call that builds the response.
	pyResponseRe = regexp.MustCompile(`\b(?:jsonify|make_response|Response|HttpResponse\w*|JsonResponse|render_template|render_template_string|render|render_to_response|abort|HTMLResponse|PlainTextResponse|ORJSONResponse|JSONResponse|flash|HTTPException)\s*\(`)
	pyReturnRe   = regexp.MustCompile(`(?m)^[ \t]*return\b`)

	// pyViewDecoRe and pyViewParamRe: a function whose return value is the
	// response -- a routed function, or a Django view (first parameter request).
	pyViewDecoRe  = regexp.MustCompile(`@[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|@(?:api_view|require_http_methods|require_POST|require_GET|require_safe|login_required|csrf_exempt|action)\b`)
	pyViewParamRe = regexp.MustCompile(`^\s*(?:self\s*,\s*)?request\b`)
	pyDefRe       = regexp.MustCompile(`(?m)^([ \t]*)(?:async\s+)?def\s+\w+\s*\(([^)]*)\)`)

	pyAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*([^\n]+)`)
)

const pyTraceback = "\x00traceback"

var pyPatterns = []exposurePattern{
	{`\btraceback\s*\.\s*(?:format_exc|format_exception|format_tb|format_stack)\s*\(|\bsys\s*\.\s*exc_info\s*\(`, exDetail, "the traceback"},
	{`\bVAR\s*\.\s*(?:__dict__|__traceback__|orig|pgerror|statement|params)\b|\bvars\s*\(\s*VAR\s*\)`, exDetail, "the exception's internals"},
	{`\b(?:str|repr|format)\s*\(\s*VAR\s*\)|\{\s*VAR\s*(?:![rsa])?\s*(?::[^}]*)?\}|\bVAR\s*\.\s*(?:args|message|msg|strerror|detail)\b|%\s*\(?\s*VAR\b|\.format\s*\([^)]*\bVAR\b`, exMessage, "the message"},
	// The exception passed whole to a response builder or a template.
	{`(?:[(,:\[]|=)\s*VAR\s*(?:[,)}\]]|$)`, exMessage, "the exception"},
}

// scanPython finds the exception handlers of a Python file and the
// responses built in them that carry the exception.
func scanPython(v view) []hit {
	var out []hit
	for _, h := range pyHandlers(v) {
		bound := len(h.vars)
		h.withAliases(v.text[h.start:h.end], pyAssignRe, pyPatterns)
		out = append(out, pyResponseHits(v, h)...)
		if len(h.vars) == bound || h.fnEnd <= h.end {
			continue
		}
		// `error = f"failed: {e}"` in the except block, rendered after it:
		// the exception's name is unbound past the block, the alias is not.
		after := handler{vars: map[string]int{}, generic: h.generic, start: h.end, end: h.fnEnd, returns: h.returns}
		for n, c := range h.vars {
			if _, original := h.bound[n]; !original {
				after.vars[n] = c
			}
		}
		out = append(out, pyResponseHits(v, after)...)
	}
	return out
}

func pyHandlers(v view) []handler {
	var out []handler
	for _, m := range pyExceptRe.FindAllStringSubmatchIndex(v.code, -1) {
		indent := m[3] - m[2]
		types := strings.TrimSpace(v.code[m[4]:m[5]])
		vars := map[string]int{pyTraceback: exDetail}
		if m[6] >= 0 {
			vars[v.code[m[6]:m[7]]] = exDetail
		}
		start := m[1]
		end := pyBlockEnd(v.code, start, indent)
		fnEnd, view := pyEnclosingDef(v.code, m[0], indent)
		bound := map[string]bool{}
		for n := range vars {
			bound[n] = true
		}
		out = append(out, handler{
			vars:    vars,
			bound:   bound,
			generic: types == "" || pyGenericRe.MatchString(types),
			start:   start, end: end, fnEnd: fnEnd,
			returns: view,
		})
	}
	for _, m := range pyErrorHandlerRe.FindAllStringSubmatchIndex(v.code, -1) {
		indent := m[3] - m[2]
		params := strings.Split(v.code[m[6]:m[7]], ",")
		name := strings.TrimSpace(strings.SplitN(params[len(params)-1], ":", 2)[0])
		if name == "" {
			continue
		}
		arg := v.code[m[4]:m[5]]
		start := m[1]
		out = append(out, handler{
			vars:    map[string]int{name: exDetail, pyTraceback: exDetail},
			generic: regexp.MustCompile(`\bException\b|\b500\b|\bBaseException\b`).MatchString(arg),
			start:   start, end: pyBlockEnd(v.code, start, indent),
			returns: true,
		})
	}
	return out
}

// pyBlockEnd returns where the block opened at start (the end of a header
// line indented by indent) ends: before the first non-blank line indented no
// deeper than the header.
func pyBlockEnd(code string, start, indent int) int {
	i := strings.IndexByte(code[start:], '\n')
	if i < 0 {
		return len(code)
	}
	i += start + 1
	for i < len(code) {
		j := strings.IndexByte(code[i:], '\n')
		line := code[i:]
		if j >= 0 {
			line = code[i : i+j]
		}
		if t := strings.TrimLeft(line, " \t"); t != "" && len(line)-len(t) <= indent {
			return i
		}
		if j < 0 {
			return len(code)
		}
		i += j + 1
	}
	return len(code)
}

// pyEnclosingDef returns where the def enclosing offset at (whose line is
// indented by indent) ends, and whether it returns the response: it is
// routed, or a Django view. -1 when at is not inside a def.
func pyEnclosingDef(code string, at, indent int) (end int, view bool) {
	defs := pyDefRe.FindAllStringSubmatchIndex(code[:at], -1)
	for i := len(defs) - 1; i >= 0; i-- {
		d := defs[i]
		defIndent := d[3] - d[2]
		if defIndent >= indent {
			continue
		}
		end = pyBlockEnd(code, d[1], defIndent)
		if pyViewParamRe.MatchString(code[d[4]:d[5]]) {
			return end, true
		}
		// The decorators directly above the def.
		lines := strings.Split(strings.TrimRight(code[:d[0]], "\n"), "\n")
		for k := len(lines) - 1; k >= 0 && strings.HasPrefix(strings.TrimSpace(lines[k]), "@"); k-- {
			if pyViewDecoRe.MatchString(lines[k]) {
				return end, true
			}
		}
		return end, false
	}
	return -1, false
}

func pyResponseHits(v view, h handler) []hit {
	var out []hit
	region := v.code[h.start:h.end]
	for _, m := range pyResponseRe.FindAllStringIndex(region, -1) {
		at := h.start + m[0]
		end := matchClose(v.code, h.start+m[1]-1, '(', ')')
		if end > at {
			if r, ok := h.report(at, v.text[at:end], pyPatterns, true); ok {
				out = append(out, r)
			}
		}
	}
	if !h.returns {
		return out
	}
	for _, m := range pyReturnRe.FindAllStringIndex(region, -1) {
		at := h.start + m[1]
		end := pyLogicalLineEnd(v.code, at)
		if r, ok := h.report(at, v.text[at:end], pyPatterns, true); ok {
			out = append(out, r)
		}
	}
	return out
}

// pyLogicalLineEnd returns the end of the logical line starting at at:
// newlines inside brackets continue it.
func pyLogicalLineEnd(code string, at int) int {
	depth := 0
	for i := at; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\n':
			if depth <= 0 && (i == 0 || code[i-1] != '\\') {
				return i
			}
		}
	}
	return len(code)
}
