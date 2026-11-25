// Package logleak reports sensitive data written to an application log
// (CWE-532) in JavaScript/TypeScript, Python and Java.
//
// THE PROPOSITION. LOGLEAK-001 claims one of:
//
//	A log call -- console.*, a logger's level methods, print, System.out --
//	is passed a credential's value (a password, token, secret, API key,
//	session cookie, card or national identity number), a request's
//	Authorization, cookie or API-key header, or a request's whole body or
//	header set (directly, through a local name assigned from it, or as a
//	NestJS @Body / Spring @RequestBody parameter).
//
//	A Django settings file that is not a development one sends all mail to
//	the console or to files (EMAIL_BACKEND console/filebased), so every
//	password-reset link and verification code lands in the log.
//
//	A sqlite connection traces every statement, with its bound values, to
//	print or a logger (set_trace_callback).
//
// Logs are kept longer, copied wider and read by more people than the data
// in them was meant for; a credential in a log is a credential anyone with
// log access holds.
//
// WHAT IS NOT REPORTED. A credential's name in the message text; a value
// whose name says it is not the secret (tokenType, passwordLength,
// isPasswordValid, tokenId); a secret only measured or tested
// (token.length, len(token), token != null, token ? … : …) or passed through
// a masking, hashing or redacting call; a single field of a request body
// that is not itself a credential.
package logleak

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/source"
)

// RuleID is LOGLEAK-001.
const RuleID = "LOGLEAK-001"

// Analyzer reports sensitive data written to logs.
type Analyzer struct{}

// NewAnalyzer constructs the analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          RuleID,
		Version:     "1.0",
		Description: "Sensitive data written to a log: a credential's value, an Authorization or cookie header, or a request's whole body passed to a log call; Django mail sent to the console; sqlite statements traced to the log (CWE-532)",
		Severity:    findings.SeverityMedium,
		// Medium: the log call and what it is given are read from the
		// source; a name is evidence of what a value holds, not proof.
		Confidence: findings.ConfidenceMedium,
		Tags:       []string{"logging", "information-exposure", "cwe-532", "owasp-a09"},
		Remediation: "Log what identifies the event, not the secret: the user id, the request id, the outcome. " +
			"Drop credentials and Authorization/Cookie headers before logging, or log a masked form (the last four characters, a hash). " +
			"Log the fields of a request you need, never the whole body or header set. " +
			"In Django, choose the console or file e-mail backend only in a development settings module or under `if DEBUG:`. " +
			"Remove sqlite trace callbacks outside debugging.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/532.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-532"},
	})
	return rs
}

// Browser code: a browser console is not an application log. Read by path,
// and by a front-end framework import without a server one (the same test
// the authz Express reader uses).
var (
	browserPathRe   = regexp.MustCompile(`(?i)(?:^|/)(?:frontend|client|web-?ui|admin-?ui|[\w-]*-vue\d*)/|(?:^|/)src/(?:components|views|composables|stores?|layouts|directives)/|(?:^|/)src/pages/(?:[^a]|a[^p]|ap[^i]|api[^/])`)
	browserImportRe = regexp.MustCompile(`(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*)['"](?:react|react-dom(?:/[\w-]+)?|vue|pinia|vue-router|svelte(?:/[\w-]+)?|solid-js|preact|@angular/[\w-]+|next/(?:navigation|router|link)|axios|ky|ofetch|swr|@tanstack/[\w-]+|@reduxjs/toolkit)['"]`)
	serverImportRe  = regexp.MustCompile(`(?:\bfrom\s*|\brequire\s*\(\s*)['"](?:express|fastify|koa|@koa/router|koa-router|@nestjs/[\w-]+|hono|restify|@hapi/hapi|polka|h3|next/server|next/headers|server-only)['"]|(?m)^\s*['"]use server['"]`)
)

var jsExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".mts": true, ".cts": true, ".tsx": true}

// ScanArtifacts reports sensitive data written to logs.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		ext := strings.ToLower(filepath.Ext(art.Path))
		var lang lexctx.Lang
		switch {
		case jsExts[ext] && !strings.HasSuffix(art.Path, ".d.ts"):
			lang = lexctx.LangJavaScript
		case ext == ".py":
			lang = lexctx.LangPython
		case ext == ".java":
			lang = lexctx.LangJava
		default:
			continue
		}
		if source.IsTestPath(art.Path) || lang == lexctx.LangJavaScript && browserPathRe.MatchString(filepath.ToSlash(art.Path)) {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil || source.IsGenerated(content) {
			continue
		}
		if lang == lexctx.LangJavaScript && browserImportRe.Match(content) && !serverImportRe.Match(content) {
			continue
		}
		for _, f := range ScanFile(art.Path, lang, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

type hit struct {
	at   int
	what string
}

// ScanFile returns the findings in one source file.
func ScanFile(path string, lang lexctx.Lang, content []byte) []findings.Finding {
	text := string(content)
	code := string(lexctx.MaskNonCode(lang, content))
	var hits []hit
	hits = append(hits, scanLogCalls(lang, text, code)...)
	if lang == lexctx.LangPython {
		hits = append(hits, scanPythonConfig(path, text, code)...)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].at < hits[j].at })
	var out []findings.Finding
	seen := map[int]bool{}
	for _, h := range hits {
		line := lexctx.LineForOffset(content, h.at)
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, findings.Finding{
			RuleID:     RuleID,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceMedium,
			Message:    "Sensitive data written to a log: " + h.what + " (CWE-532)",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-532", "language": lang.String()},
		})
	}
	return out
}

// matchClose returns the index of the bracket closing the one at open, or -1.
func matchClose(s string, open int, o, c byte) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

var (
	// Django settings: the console and file backends write every message.
	djangoMailRe = regexp.MustCompile(`(?m)^([ \t]*)EMAIL_BACKEND\s*=.*["']django\.core\.mail\.backends\.(console|filebased)\.EmailBackend["']`)
	// A settings module meant for development.
	devSettingsRe  = regexp.MustCompile(`(?i)(?:^|[/_.-])(?:dev|develop|development|local|test|tests|testing|ci)(?:[/_.-]|$)`)
	settingsFileRe = regexp.MustCompile(`(?i)(?:^|/)settings(?:[/_.][^/]*)?\.py$|(?:^|/)settings/[^/]+\.py$`)
	ifDebugRe      = regexp.MustCompile(`^\s*(?:if|elif)\b[^#\n]*\bDEBUG\b`)
	// sqlite: every statement, values bound in, to the log.
	traceCallbackRe = regexp.MustCompile(`\.\s*set_trace_callback\s*\(\s*(?:print|(?:self\s*\.\s*)?(?:logger|logging|log|LOG|_logger|_log)\s*\.\s*\w+)\s*\)`)
)

// scanPythonConfig reports the Django mail backend and sqlite trace cases.
func scanPythonConfig(path, text, code string) []hit {
	var out []hit
	p := filepath.ToSlash(path)
	if settingsFileRe.MatchString(p) && !devSettingsRe.MatchString(strings.TrimSuffix(p, ".py")) {
		// The backend is named in a string, so this reads the text; the
		// assignment itself must be code, not a comment.
		for _, m := range djangoMailRe.FindAllStringSubmatchIndex(text, -1) {
			if code[m[3]] != 'E' || underDebug(text, m[0], m[3]-m[2]) {
				continue
			}
			out = append(out, hit{at: m[2] + (m[3] - m[2]), what: "all outgoing e-mail, password-reset links included, goes to the " + map[string]string{"console": "console", "filebased": "file system"}[text[m[4]:m[5]]] + " (Django " + text[m[4]:m[5]] + " EmailBackend outside a development settings module)"})
		}
	}
	for _, m := range traceCallbackRe.FindAllStringIndex(code, -1) {
		out = append(out, hit{at: m[0], what: "every sqlite statement, with its bound values, is traced to the log (set_trace_callback)"})
	}
	return out
}

// underDebug reports whether the line at off, indented by indent, sits in an
// `if DEBUG` block.
func underDebug(text string, off, indent int) bool {
	if indent == 0 {
		return false
	}
	lines := strings.Split(text[:off], "\n")
	for i := len(lines) - 2; i >= 0; i-- {
		l := lines[i]
		t := strings.TrimLeft(l, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(l)-len(t) < indent {
			return ifDebugRe.MatchString(l)
		}
	}
	return false
}
