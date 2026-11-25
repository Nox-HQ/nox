package appconfig

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// Debug settings in Spring and Java EE configuration files, reported as
// APPCFG-001 (CWE-215): each one hands the client, or anyone who can reach
// the port, what only a developer should see.
//
//   - server.error.include-stacktrace=always (or on-param): every error
//     response carries the stack trace.
//   - management.endpoints.web.exposure.include=*: every actuator endpoint
//     over HTTP, among them env, configprops, heapdump and threaddump.
//   - spring.h2.console.enabled=true: the H2 web console, which runs SQL.
//   - JSF PROJECT_STAGE Development: detailed error pages and component
//     trees.
//
// A profile or file named for development (application-dev.yml,
// application-local.properties) is where these belong, and is not read.
var (
	propsStacktraceRe = regexp.MustCompile(`(?mi)^[ \t]*[\w.-]*include-stacktrace[ \t]*[=:][ \t]*["']?(always|on[-_]param|on[-_]trace[-_]param)\b`)
	yamlStacktraceRe  = regexp.MustCompile(`(?mi)^[ \t]*include-stacktrace[ \t]*:[ \t]*["']?(always|on[-_]param|on[-_]trace[-_]param)\b`)
	propsExposeAllRe  = regexp.MustCompile(`(?m)^[ \t]*management\.endpoints\.web\.exposure\.include[ \t]*[=:][ \t]*["']?\*["']?[ \t]*$`)
	yamlIncludeAllRe  = regexp.MustCompile(`(?m)^([ \t]*)include[ \t]*:[ \t]*(?:["']\*["']|\[[ \t]*["']\*["'][ \t]*\])[ \t]*(?:#.*)?$`)
	propsH2ConsoleRe  = regexp.MustCompile(`(?m)^[ \t]*spring\.h2\.console\.enabled[ \t]*[=:][ \t]*true\b`)
	yamlEnabledTrueRe = regexp.MustCompile(`(?m)^([ \t]*)enabled[ \t]*:[ \t]*true\b`)
	jsfStageRe        = regexp.MustCompile(`(?s)<param-name>\s*(?:jakarta|javax)\.faces\.PROJECT_STAGE\s*</param-name>\s*(?:<!--.*?-->\s*)*<param-value>\s*Development\s*</param-value>`)
	// A configuration file for development or tests.
	devConfigRe = regexp.MustCompile(`(?i)(?:^|[-_.])(?:dev|develop|development|local|test|tests|testing|ci)(?:[-_.]|$)`)
)

// scanDebugConfig reports debug settings in Spring properties and YAML, and
// in a JSF web.xml.
func scanDebugConfig(path string, content []byte) []findings.Finding {
	base := strings.ToLower(filepath.Base(filepath.ToSlash(path)))
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if devConfigRe.MatchString(stem) {
		return nil
	}
	var out []findings.Finding
	add := func(at int, msg string) {
		out = append(out, debugFinding(path, content, at, msg))
	}
	const (
		stackMsg  = "Error responses include the stack trace (include-stacktrace)"
		exposeMsg = "Every Spring Boot actuator endpoint is exposed over HTTP (exposure.include=*), env and heapdump among them"
		h2Msg     = "The H2 web console, which runs SQL against the database, is enabled"
	)
	switch {
	case strings.HasSuffix(base, ".properties"):
		for _, m := range propsStacktraceRe.FindAllIndex(content, -1) {
			add(m[0], stackMsg)
		}
		for _, m := range propsExposeAllRe.FindAllIndex(content, -1) {
			add(m[0], exposeMsg)
		}
		for _, m := range propsH2ConsoleRe.FindAllIndex(content, -1) {
			add(m[0], h2Msg)
		}
	case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		for _, m := range yamlStacktraceRe.FindAllIndex(content, -1) {
			add(m[0], stackMsg)
		}
		for _, m := range yamlIncludeAllRe.FindAllSubmatchIndex(content, -1) {
			if yamlParentIs(content, m[0], m[3]-m[2], "exposure") {
				add(m[0], exposeMsg)
			}
		}
		for _, m := range yamlEnabledTrueRe.FindAllSubmatchIndex(content, -1) {
			if yamlParentIs(content, m[0], m[3]-m[2], "console") && yamlAncestorIs(content, m[0], "h2") {
				add(m[0], h2Msg)
			}
		}
	case strings.HasSuffix(base, ".xml"):
		for _, m := range jsfStageRe.FindAllIndex(content, -1) {
			add(m[0], "JSF runs in the Development project stage (PROJECT_STAGE), with detailed error pages")
		}
	}
	return out
}

func debugFinding(path string, content []byte, at int, msg string) findings.Finding {
	r := builtin[0]
	line := lexctx.LineForOffset(content, at)
	return findings.Finding{
		RuleID:     r.id,
		Severity:   r.severity,
		Confidence: findings.ConfidenceHigh,
		Message:    msg,
		Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Metadata:   map[string]string{"cwe": r.cwe, "language": "config"},
	}
}

// yamlParentIs reports whether the YAML key at off, indented by indent,
// sits directly under a key named parent.
func yamlParentIs(content []byte, off, indent int, parent string) bool {
	k, ok := yamlParent(content, off, indent)
	return ok && k == parent
}

// yamlAncestorIs reports whether any enclosing key of the line at off is
// named name.
func yamlAncestorIs(content []byte, off int, name string) bool {
	indent := len(lineAt(content, off)) - len(bytes.TrimLeft(lineAt(content, off), " \t"))
	for indent > 0 {
		k, ok := yamlParent(content, off, indent)
		if !ok {
			return false
		}
		if k == name {
			return true
		}
		off, indent = yamlParentOffset(content, off, indent)
		if off < 0 {
			return false
		}
	}
	return false
}

func lineAt(content []byte, off int) []byte {
	start := bytes.LastIndexByte(content[:off], '\n') + 1
	end := bytes.IndexByte(content[off:], '\n')
	if end < 0 {
		return content[start:]
	}
	return content[start : off+end]
}

// yamlParentOffset returns the offset and indentation of the nearest line
// above off indented less than indent, or -1 when there is none.
func yamlParentOffset(content []byte, off, indent int) (int, int) {
	lineStart := bytes.LastIndexByte(content[:off], '\n') + 1
	for lineStart > 0 {
		prevEnd := lineStart - 1
		prevStart := bytes.LastIndexByte(content[:prevEnd], '\n') + 1
		l := content[prevStart:prevEnd]
		t := bytes.TrimLeft(l, " \t")
		if len(t) > 0 && t[0] != '#' {
			if in := len(l) - len(t); in < indent {
				return prevStart, in
			}
		}
		lineStart = prevStart
	}
	return -1, 0
}

// yamlParent returns the key of the nearest line above off indented less
// than indent.
func yamlParent(content []byte, off, indent int) (string, bool) {
	p, _ := yamlParentOffset(content, off, indent)
	if p < 0 {
		return "", false
	}
	l := bytes.TrimLeft(lineAt(content, p), " \t")
	key, _, found := bytes.Cut(l, []byte(":"))
	if !found {
		return "", false
	}
	return strings.Trim(string(bytes.TrimSpace(key)), `"'`), true
}
