package confirm

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// EntryPoint is the concrete HTTP surface a confirmation probe targets: the
// route to POST to and the untrusted request fields to inject payloads into.
type EntryPoint struct {
	Route  string
	Fields []string
}

var (
	reRouteDecorator = regexp.MustCompile(`\.route\(\s*['"]([^'"]+)['"]`)
	// Reads of untrusted request fields: request.json[...] / body.get(...) etc.
	reRequestField = regexp.MustCompile(`(?:request\.json|body|data|payload)(?:\.get\(\s*|\[\s*)['"]([^'"]+)['"]`)
)

// RecoverEntryPointFromSource parses a Flask-style app source file and recovers
// the (route, fields) for a handler function. The static finding says *some*
// http_body field is tainted into the prompt; the confirm loop discovers *which*
// field is actually exploitable by probing each. This mirrors the research
// prototype and is deliberately framework/pattern-based — see docs/confirm.md
// "Limits": other frameworks (FastAPI, Django, Go handlers) or indirect taint
// need explicit --route/--fields instead.
func RecoverEntryPointFromSource(appSrcPath, functionName string) (EntryPoint, error) {
	data, err := os.ReadFile(appSrcPath)
	if err != nil {
		return EntryPoint{}, fmt.Errorf("read app source %s: %w", appSrcPath, err)
	}
	return recoverEntryPoint(string(data), functionName)
}

func recoverEntryPoint(src, functionName string) (EntryPoint, error) {
	lines := strings.Split(src, "\n")
	defRe := regexp.MustCompile(`^\s*def\s+` + regexp.QuoteMeta(functionName) + `\s*\(`)

	defIdx := -1
	for i, ln := range lines {
		if defRe.MatchString(ln) {
			defIdx = i
			break
		}
	}
	if defIdx == -1 {
		return EntryPoint{}, fmt.Errorf("function %q not found in app source", functionName)
	}

	// Nearest @*.route(...) decorator above the def (scan a small window up).
	route := ""
	for i := defIdx - 1; i >= 0 && i >= defIdx-8; i-- {
		if m := reRouteDecorator.FindStringSubmatch(lines[i]); m != nil {
			route = m[1]
			break
		}
	}

	// Function body: until the next top-level def / decorator at column 0.
	var body []string
	for _, ln := range lines[defIdx+1:] {
		if ln != "" && !isSpace(ln[0]) && (strings.HasPrefix(ln, "def ") || strings.HasPrefix(ln, "@")) {
			break
		}
		body = append(body, ln)
	}
	bodyText := strings.Join(body, "\n")

	var fields []string
	seen := map[string]struct{}{}
	for _, m := range reRequestField.FindAllStringSubmatch(bodyText, -1) {
		f := m[1]
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			fields = append(fields, f)
		}
	}

	return EntryPoint{Route: route, Fields: fields}, nil
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }
