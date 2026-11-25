package logleak

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

var (
	// A log call; the match ends at the "(" opening its arguments.
	jsLogRe = regexp.MustCompile(`\b(?:console|(?:this\s*\.\s*)?(?:log|logger|LOG|LOGGER|[A-Za-z_$][\w$]*(?:Log|Logger))|(?:req|request|app|fastify|server|ctx)\s*\.\s*log)\s*\.\s*(?:log|info|warn|error|debug|trace|fatal|verbose)\s*\(`)
	pyLogRe = regexp.MustCompile(`\b(?:(?:self\s*\.\s*)?(?:logging|logger|log|LOG|LOGGER|_logger|_log|L|[A-Za-z_]\w*_logger|[A-Za-z_]\w*Logger))\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|fatal)\s*\(|\bprint\s*\(`)
	// Python 2: print as a statement; its arguments run to the end of the line.
	pyPrintStmtRe = regexp.MustCompile(`(?m)^[ \t]*print[ \t]+[^(\s=]`)
	javaLogRe     = regexp.MustCompile(`\b(?:log|LOG|logger|LOGGER|Log|[A-Za-z_]\w*(?:Logger|LOGGER|Log))\s*\.\s*(?:trace|debug|info|warn|warning|error|fatal|severe|fine|finer|finest|tracef|debugf|infof|warnf|errorf|log)\s*\(|\bSystem\s*\.\s*(?:out|err)\s*\.\s*print(?:ln|f)?\s*\(`)

	// A request's whole body or header set, by language.
	jsPayloadRe = regexp.MustCompile(`\b(?:req|request|ctx\s*\.\s*request)\s*\.\s*(?:body|headers|cookies|rawBody)\b`)
	pyPayloadRe = regexp.MustCompile(`\b(?:self\s*\.\s*)?request\s*\.\s*(?:body|data|form|json|POST|headers|cookies|META|get_json\s*\(\s*[^)]*\)|get_data\s*\(\s*[^)]*\)|body\s*\(\s*\)|json\s*\(\s*\))`)
	// The payload is narrowed to one field: request.form["email"],
	// req.body.email, request.headers.get("x").
	jsFieldAfterRe = regexp.MustCompile(`^\s*(?:\?\.|\.)\s*[A-Za-z_$]|^\s*\[`)
	pyFieldAfterRe = regexp.MustCompile(`^\s*\.\s*(?:get|getlist|get_json|items|keys|values)\s*\(|^\s*\[|^\s*\.\s*[A-Za-z_]\w*\s*\(?`)
	pyWholeAfterRe = regexp.MustCompile(`^\s*\.\s*(?:decode|items|copy|dict|to_dict)\s*\(`)

	// A header read that names a credential header.
	credHeaderRe = regexp.MustCompile(`(?i)(?:headers?\s*(?:\.\s*get\s*\(|\[)|getHeader\s*\(|\.\s*get\s*\(|\.\s*header\s*\()\s*["'](?:authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-csrf-token)["']|\bheaders\s*(?:\?\.|\.)\s*(?:authorization|cookie)\b|\bHTTP_AUTHORIZATION\b|\bHTTP_COOKIE\b`)
	// A credential read from the payload by key: request.form["password"].
	credKeyRe = regexp.MustCompile(`(?i)(?:\.\s*get(?:Parameter)?\s*\(|\[)\s*["'][\w-]*(?:password|passwd|secret|token|api[_-]?key|otp|ssn|cvv)[\w-]*["']`)

	// Aliases: `body = request.body.decode()`, `const payload = req.body`.
	jsAssignRe = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*([^;\n]+)`)
	pyAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*([^\n]+)`)
	// Body parameters: NestJS @Body() dto, Spring @RequestBody Dto dto.
	nestBodyRe   = regexp.MustCompile(`@Body\s*\(\s*\)\s*([A-Za-z_$][\w$]*)\s*(?::\s*([\w$.<>\[\]]+))?`)
	springBodyRe = regexp.MustCompile(`@RequestBody\s+(?:@\w+(?:\([^)]*\))?\s+)*(?:final\s+)?([\w.<>,?\[\]\s]+?)\s+([A-Za-z_]\w*)\s*[,)]`)
	// A body parameter counts when its name or type says it carries
	// credentials or payment data: a login or sign-up form, a reset, a card.
	credentialBodyRe = regexp.MustCompile(`(?i)login|sign_?in|sign_?up|regist|password|passwd|credential|auth|reset|token|secret|card|payment|payout|bank|kyc`)
)

// payloadAlias is a name standing for a request's whole payload, valid in
// [from, to).
type payloadAlias struct {
	name     string
	from, to int
}

// scanLogCalls reports log calls whose arguments carry sensitive data.
func scanLogCalls(lang lexctx.Lang, text, code string) []hit {
	aliases := payloadAliases(lang, text, code)
	var out []hit
	check := func(at, argsFrom, argsTo int) {
		if argsTo <= argsFrom {
			return
		}
		if what := sensitiveArgs(lang, text[argsFrom:argsTo], code[argsFrom:argsTo], argsFrom, aliases); what != "" {
			out = append(out, hit{at: at, what: what})
		}
	}
	var re *regexp.Regexp
	switch lang {
	case lexctx.LangJavaScript:
		re = jsLogRe
	case lexctx.LangPython:
		re = pyLogRe
	case lexctx.LangJava:
		re = javaLogRe
	}
	for _, m := range re.FindAllStringIndex(code, -1) {
		open := m[1] - 1
		check(m[0], open+1, matchClose(code, open, '(', ')'))
	}
	if lang == lexctx.LangPython {
		for _, m := range pyPrintStmtRe.FindAllStringIndex(code, -1) {
			end := strings.IndexByte(code[m[1]:], '\n')
			if end < 0 {
				end = len(code) - m[1]
			}
			start := strings.Index(code[m[0]:], "print") + m[0]
			check(start, start+len("print"), m[1]+end)
		}
	}
	return out
}

// sensitiveArgs names what a log call's arguments disclose, or "".
func sensitiveArgs(lang lexctx.Lang, text, code string, base int, aliases []payloadAlias) string {
	if credHeaderRe.MatchString(text) {
		return "a request's credential header (Authorization, Cookie or API key)"
	}
	if credKeyRe.MatchString(text) {
		return "a credential read from the request"
	}
	if wholePayload(lang, code) {
		return "a request's whole body or header set"
	}
	for _, a := range aliases {
		if base < a.from || base >= a.to {
			continue
		}
		for _, loc := range wordIndexes(code, a.name) {
			if !narrowed(lang, code[loc[1]:]) {
				return "a request's whole body (as `" + a.name + "`)"
			}
		}
	}
	if name := credentialValue(code); name != "" {
		return "a credential's value (`" + name + "`)"
	}
	return ""
}

// wholePayload reports a request body or header set passed whole.
func wholePayload(lang lexctx.Lang, code string) bool {
	var re *regexp.Regexp
	switch lang {
	case lexctx.LangJavaScript:
		re = jsPayloadRe
	case lexctx.LangPython:
		re = pyPayloadRe
	default:
		return false
	}
	for _, m := range re.FindAllStringIndex(code, -1) {
		if !narrowed(lang, code[m[1]:]) {
			return true
		}
	}
	return false
}

// narrowed reports whether what follows a payload expression picks one part
// of it.
func narrowed(lang lexctx.Lang, after string) bool {
	if lang == lexctx.LangPython {
		if pyWholeAfterRe.MatchString(after) {
			return false
		}
		return pyFieldAfterRe.MatchString(after)
	}
	return jsFieldAfterRe.MatchString(after)
}

var identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// wordIndexes returns where name occurs as a whole identifier in code, not
// as a property of something else.
func wordIndexes(code, name string) [][]int {
	var out [][]int
	for _, m := range identRe.FindAllStringIndex(code, -1) {
		if code[m[0]:m[1]] != name {
			continue
		}
		before := strings.TrimRight(code[:m[0]], " \t")
		if strings.HasSuffix(before, ".") {
			continue
		}
		out = append(out, m)
	}
	return out
}

// payloadAliases collects the names bound to a request's whole payload and
// where each is in scope.
func payloadAliases(lang lexctx.Lang, text, code string) []payloadAlias {
	var out []payloadAlias
	switch lang {
	case lexctx.LangJavaScript:
		for _, m := range jsAssignRe.FindAllStringSubmatchIndex(code, -1) {
			if rhs := code[m[4]:m[5]]; wholePayload(lang, rhs) {
				out = append(out, payloadAlias{code[m[2]:m[3]], m[1], blockEnd(code, m[0])})
			}
		}
		for _, m := range nestBodyRe.FindAllStringSubmatchIndex(code, -1) {
			if credentialBodyRe.MatchString(code[m[2]:m[3]]) || m[4] >= 0 && credentialBodyRe.MatchString(code[m[4]:m[5]]) {
				out = append(out, payloadAlias{code[m[2]:m[3]], m[1], bodyEnd(code, m[1])})
			}
		}
	case lexctx.LangPython:
		for _, m := range pyAssignRe.FindAllStringSubmatchIndex(code, -1) {
			if rhs := code[m[4]:m[5]]; wholePayload(lang, rhs) {
				out = append(out, payloadAlias{code[m[2]:m[3]], m[1], pyDefEnd(code, m[0])})
			}
		}
	case lexctx.LangJava:
		for _, m := range springBodyRe.FindAllStringSubmatchIndex(code, -1) {
			if credentialBodyRe.MatchString(code[m[2]:m[5]]) {
				out = append(out, payloadAlias{code[m[4]:m[5]], m[1], bodyEnd(code, m[1])})
			}
		}
	}
	_ = text
	return out
}

// blockEnd returns the end of the innermost brace block holding off.
func blockEnd(code string, off int) int {
	depth := 0
	for i := off - 1; i >= 0; i-- {
		switch code[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				if e := matchClose(code, i, '{', '}'); e > 0 {
					return e
				}
				return len(code)
			}
			depth--
		}
	}
	return len(code)
}

// bodyEnd returns the end of the function body opening after a parameter.
func bodyEnd(code string, off int) int {
	open := strings.IndexByte(code[off:], '{')
	if open < 0 {
		return len(code)
	}
	if e := matchClose(code, off+open, '{', '}'); e > 0 {
		return e
	}
	return len(code)
}

var pyDefLineRe = regexp.MustCompile(`^[ \t]*(?:async[ \t]+)?def[ \t]`)

// pyDefEnd returns the end of the Python function holding the line at off.
func pyDefEnd(code string, off int) int {
	lineStart := strings.LastIndexByte(code[:off+1], '\n') + 1
	indent := indentOf(code[lineStart:])
	// Find the enclosing def: the nearest earlier def line indented less.
	defIndent := -1
	for i := lineStart - 1; i > 0; {
		ls := strings.LastIndexByte(code[:i], '\n') + 1
		l := code[ls:i]
		if strings.TrimSpace(l) != "" && pyDefLineRe.MatchString(l) && indentOf(l) < indent {
			defIndent = indentOf(l)
			break
		}
		i = ls - 1
	}
	if defIndent < 0 {
		return len(code)
	}
	pos := strings.IndexByte(code[off:], '\n')
	if pos < 0 {
		return len(code)
	}
	pos += off + 1
	for pos < len(code) {
		e := strings.IndexByte(code[pos:], '\n')
		if e < 0 {
			e = len(code) - pos
		}
		l := code[pos : pos+e]
		if strings.TrimSpace(l) != "" && indentOf(l) <= defIndent {
			return pos
		}
		pos += e + 1
	}
	return len(code)
}

func indentOf(l string) int {
	return len(l) - len(strings.TrimLeft(l, " \t"))
}
