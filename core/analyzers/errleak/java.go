package errleak

import (
	"regexp"
	"strings"
)

var (
	// javaCatchRe: catch (Type e) {, catch (final A | B e) {.
	javaCatchRe = regexp.MustCompile(`\bcatch\s*\(\s*(?:final\s+)?([\w.$|\s]+?)\s+([A-Za-z_$][\w$]*)\s*\)\s*\{`)
	// javaHandlerRe: a Spring @ExceptionHandler and the method under it.
	javaHandlerRe = regexp.MustCompile(`@ExceptionHandler\b\s*(?:\(([^)]*)\))?[^{;]*?\(([^)]*)\)\s*(?:throws[^{]*)?\{`)
	javaParamRe   = regexp.MustCompile(`(?:final\s+)?([\w.$]*(?:Exception|Throwable|Error))\s+([A-Za-z_$][\w$]*)`)

	javaGenericRe = regexp.MustCompile(`\b(?:Exception|Throwable|RuntimeException|Error|SQLException|\w*SQL\w*Exception|DataAccessException|IOException|UncheckedIOException|PersistenceException|HibernateException|JDBCException|JsonProcessingException|NullPointerException|IllegalStateException|ServletException|NamingException)\b`)

	// javaResponseRe: a call or statement that writes the response.
	javaResponseRe = regexp.MustCompile(`\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:write|print|println|printf|append|format)\s*\(|\bout\s*\.\s*(?:print|println|write)\s*\(|\.\s*(?:addAttribute|addFlashAttribute|addObject|sendError|body|bodyValue|entity)\s*\(|(?:\.\s*|\b)(?:addActionError|addActionMessage|addFieldError)\s*\(|\brequest\s*\.\s*setAttribute\s*\(|\bnew\s+ResponseEntity\s*(?:<[^>]*>)?\s*\(|\b[A-Za-z_$][\w$]*\s*\.\s*printStackTrace\s*\(\s*[^)\s]`)
	javaReturnRe   = regexp.MustCompile(`\breturn\b`)
	javaWebRe      = regexp.MustCompile(`@(?:RestController|Controller|ControllerAdvice|RestControllerAdvice|Path)\b|\bextends\s+(?:HttpServlet|ActionSupport)\b`)

	javaAssignRe = regexp.MustCompile(`(?:String|var|Object|StringBuilder|final\s+String)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]+);`)
)

var javaPatterns = []exposurePattern{
	{`\bVAR\s*\.\s*(?:getStackTrace|printStackTrace)\b|\b(?:ExceptionUtils|Throwables)\s*\.\s*(?:getStackTrace|getFullStackTrace|getStackTraceAsString|getRootCauseStackTrace)\s*\(\s*VAR\b`, exDetail, "the stack trace"},
	// Passed whole as an argument: serialised with its stack trace, or
	// rendered by a template.
	{`[(,]\s*VAR\s*[,)]`, exDetail, "the exception object"},
	{`\bVAR\s*\.\s*(?:getMessage|getLocalizedMessage|toString)\s*\(|\bString\s*\.\s*valueOf\s*\(\s*VAR\b|\+\s*VAR\b\s*(?:[^.\w$]|$)|\bVAR\s*\+`, exMessage, "the message"},
}

// scanJava finds the exception handlers of a Java file and the response
// writes in them that carry the exception.
func scanJava(v view) []hit {
	web := javaWebRe.MatchString(v.code)
	var out []hit
	for _, h := range javaHandlers(v, web) {
		h.withAliases(v.text[h.start:h.end], javaAssignRe, javaPatterns)
		out = append(out, javaResponseHits(v, h)...)
	}
	return out
}

func javaHandlers(v view, web bool) []handler {
	var out []handler
	for _, m := range javaCatchRe.FindAllStringSubmatchIndex(v.code, -1) {
		open := m[1] - 1
		out = append(out, handler{
			vars:    map[string]int{v.code[m[4]:m[5]]: exDetail},
			generic: javaGenericRe.MatchString(v.code[m[2]:m[3]]),
			start:   open, end: matchClose(v.code, open, '{', '}'),
			// In a controller, a return in a catch block returns the response.
			returns: web,
		})
	}
	for _, m := range javaHandlerRe.FindAllStringSubmatchIndex(v.code, -1) {
		p := javaParamRe.FindStringSubmatch(v.code[m[4]:m[5]])
		if p == nil {
			continue
		}
		handled := ""
		if m[2] >= 0 {
			handled = v.code[m[2]:m[3]]
		}
		open := m[1] - 1
		out = append(out, handler{
			vars:    map[string]int{p[2]: exDetail},
			generic: regexp.MustCompile(`\b(?:Exception|Throwable|RuntimeException)\.class\b`).MatchString(handled) || handled == "" && javaGenericRe.MatchString(p[1]),
			start:   open, end: matchClose(v.code, open, '{', '}'),
			returns: true,
		})
	}
	return out
}

func javaResponseHits(v view, h handler) []hit {
	if h.end <= h.start {
		return nil
	}
	var out []hit
	region := v.code[h.start:h.end]
	try := func(at, end int) {
		if end > at {
			if r, ok := h.report(at, v.text[at:end], javaPatterns, true); ok {
				out = append(out, r)
			}
		}
	}
	for _, m := range javaResponseRe.FindAllStringIndex(region, -1) {
		at := h.start + m[0]
		end := strings.IndexByte(v.code[at:], ';')
		if end < 0 {
			continue
		}
		try(at, at+end)
	}
	if h.returns {
		for _, m := range javaReturnRe.FindAllStringIndex(region, -1) {
			at := h.start + m[0]
			end := strings.IndexByte(v.code[at:], ';')
			if end < 0 {
				continue
			}
			try(at, at+end)
		}
	}
	return out
}
