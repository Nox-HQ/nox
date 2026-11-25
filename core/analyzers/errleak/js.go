package errleak

import (
	"regexp"
	"strings"
)

var (
	// jsCatchRe: catch (e) {, catch (e: unknown) {.
	jsCatchRe = regexp.MustCompile(`\bcatch\s*\(\s*([A-Za-z_$][\w$]*)\s*(?::[^)]*)?\)\s*\{`)
	// jsPromiseCatchRe: .catch(e => ..., .catch((e) => ..., .catch(function (e) ...
	jsPromiseCatchRe = regexp.MustCompile(`\.catch\s*\(\s*(?:async\s+)?(?:\(\s*([A-Za-z_$][\w$]*)[^)]*\)\s*(?::[^=]*)?=>|([A-Za-z_$][\w$]*)\s*=>|function\s*[\w$]*\s*\(\s*([A-Za-z_$][\w$]*))`)
	// jsErrFirstRe: a function whose first parameter is the error -- a
	// node-style callback or an Express error middleware.
	jsErrFirstRe = regexp.MustCompile(`(?:\bfunction\s*[\w$]*\s*\(|\(\s*)(err|error|e|ex|exc)\s*(?::[^,)]*)?,\s*[A-Za-z_$][\w$]*[^()]*\)\s*(?::[^={]*)?(?:=>)?\s*\{`)

	// jsDistinguishRe: the handler tells error kinds apart, so a message it
	// sends was chosen.
	jsDistinguishRe = regexp.MustCompile(`\binstanceof\b|\.\s*(?:name|code|status|statusCode|kind|type)\s*[!=]==?|\bisAxiosError\b|\bZodError\b|\bValidationError\b|\bHttpError\b|\bisHttpError\b`)

	// jsResponseRe: a call that writes the response; group 1 marks where its
	// argument list opens (the last "(").
	jsResponseRe = regexp.MustCompile(`\b(?:res|response|resp)\s*\.\s*(?:status\s*\([^()]*\)\s*\.\s*)?(?:send|json|end|write|render|jsonp)\s*\(|\breply\s*\.\s*(?:(?:code|status)\s*\([^()]*\)\s*\.\s*)?send\s*\(|\b(?:NextResponse|Response)\s*\.\s*json\s*\(|\bnew\s+(?:Next)?Response\s*\(`)
	// jsCtxBodyRe: Koa writes the response by assignment.
	jsCtxBodyRe = regexp.MustCompile(`\bctx\s*\.\s*body\s*=`)
	// jsClientErrorRe: a 4xx answer. A JavaScript catch is untyped and also
	// catches the errors the application throws for the user ("amount must be
	// positive"); a message sent back as a client error is that, by choice.
	jsClientErrorRe = regexp.MustCompile(`\b(?:status|code|sendStatus)\s*\(\s*4\d\d\b|\bstatus\s*:\s*4\d\d\b|\b[A-Z]\w*(?:BadRequest|NotFound|Unauthorized|Forbidden|Conflict|Unprocessable)\w*Exception\b`)
	// jsNestThrowRe: NestJS sends an HttpException's message to the client.
	jsNestThrowRe = regexp.MustCompile(`\bthrow\s+new\s+[A-Z]\w*Exception\s*\(`)

	jsAssignRe   = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*([^;\n]+)`)
	jsDestructRe = regexp.MustCompile(`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([A-Za-z_$][\w$]*)\b`)
)

var jsPatterns = []exposurePattern{
	{`\bVAR\s*\??\.\s*stack\b`, exDetail, "the stack trace"},
	{`\bVAR\s*\??\.\s*(?:sql|sqlMessage|sqlState|query|detail|original|parent)\b`, exDetail, "the SQL or driver detail"},
	// Passed as an argument or a property value, not concatenated or
	// interpolated (those give only "Name: message").
	{`(?:[(,:\[]|[^$]\{)\s*VAR\s*(?:[,)}\]]|$)`, exDetail, "the exception object"},
	{`\butil\s*\.\s*inspect\s*\(\s*VAR\b|\bJSON\s*\.\s*stringify\s*\(\s*VAR\b|\bserializeError\s*\(\s*VAR\b`, exDetail, "the exception object"},
	{`\bVAR\s*\??\.\s*message\b`, exMessage, "the message"},
	{`\bString\s*\(\s*VAR\s*\)|\bVAR\s*\??\.\s*toString\s*\(|\$\{\s*VAR\s*\}|\+\s*VAR\b\s*(?:[^.\w$]|$)`, exMessage, "the message"},
}

// scanJS finds the exception handlers of a JavaScript/TypeScript file and
// the response writes in them that carry the exception.
func scanJS(v view) []hit {
	nest := strings.Contains(v.text, "@nestjs/")
	var out []hit
	for _, h := range jsHandlers(v) {
		body := v.text[h.start:h.end]
		h.withAliases(body, jsAssignRe, jsPatterns)
		for _, m := range jsDestructRe.FindAllStringSubmatch(body, -1) {
			if _, ok := h.vars[m[2]]; !ok {
				continue
			}
			for _, n := range strings.Split(m[1], ",") {
				n = strings.TrimSpace(strings.SplitN(n, ":", 2)[0])
				switch n {
				case "stack":
					h.vars[n] = exDetail
				case "message":
					h.vars[n] = exMessage
				}
			}
		}
		out = append(out, jsResponseHits(v, h, nest)...)
	}
	return out
}

// jsHandlers returns every exception handler in the file.
func jsHandlers(v view) []handler {
	var out []handler
	add := func(name string, start, end int) {
		if name == "" || end <= start {
			return
		}
		body := v.code[start:end]
		out = append(out, handler{vars: map[string]int{name: exDetail}, generic: !jsDistinguishRe.MatchString(body), start: start, end: end})
	}
	for _, m := range jsCatchRe.FindAllStringSubmatchIndex(v.code, -1) {
		open := m[1] - 1
		add(v.code[m[2]:m[3]], open, matchClose(v.code, open, '{', '}'))
	}
	for _, m := range jsPromiseCatchRe.FindAllStringSubmatchIndex(v.code, -1) {
		name := ""
		for g := 1; g <= 3; g++ {
			if m[2*g] >= 0 {
				name = v.code[m[2*g]:m[2*g+1]]
			}
		}
		open := strings.Index(v.code[m[0]:], "(") + m[0]
		add(name, m[1], matchClose(v.code, open, '(', ')'))
	}
	for _, m := range jsErrFirstRe.FindAllStringSubmatchIndex(v.code, -1) {
		open := m[1] - 1
		add(v.code[m[2]:m[3]], open, matchClose(v.code, open, '{', '}'))
	}
	return out
}

// jsResponseHits returns the response writes in h that carry its exception.
func jsResponseHits(v view, h handler, nest bool) []hit {
	var out []hit
	region := v.code[h.start:h.end]
	try := func(at, argsEnd int) {
		if argsEnd <= at {
			return
		}
		args := v.text[at:argsEnd]
		if r, ok := h.report(at, args, jsPatterns, !jsClientErrorRe.MatchString(args)); ok {
			out = append(out, r)
		}
	}
	for _, m := range jsResponseRe.FindAllStringIndex(region, -1) {
		at := h.start + m[0]
		open := h.start + m[1] - 1
		try(at, matchClose(v.code, open, '(', ')'))
	}
	for _, m := range jsCtxBodyRe.FindAllStringIndex(region, -1) {
		at := h.start + m[0]
		end := strings.IndexAny(v.code[at:], ";\n")
		if end < 0 {
			end = len(v.code) - at
		}
		try(at, at+end)
	}
	if nest {
		for _, m := range jsNestThrowRe.FindAllStringIndex(region, -1) {
			at := h.start + m[0]
			open := h.start + m[1] - 1
			try(at, matchClose(v.code, open, '(', ')'))
		}
	}
	return out
}
