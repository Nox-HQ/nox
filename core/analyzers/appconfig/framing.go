package appconfig

import (
	"regexp"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// RuleFramingOff (APPCFG-009) reports source that switches a response's
// framing protection off (CWE-1021), where the developer writes the decision
// down:
//
//   - Spring Security: `frameOptions().disable()`, `frameOptions(f -> f.disable())`,
//     `frameOptions(FrameOptionsConfig::disable)`, the Kotlin DSL
//     `frameOptions { disable() }`, and `headers().disable()` /
//     `headers(h -> h.disable())`, which drops X-Frame-Options with every other
//     security header.
//   - Any language: X-Frame-Options set to ALLOWALL or `*` (not values a
//     browser knows, so the page is framed as if the header were absent),
//     the header removed or deleted from a response, or a Content-Security-Policy
//     whose frame-ancestors is `*`.
//   - Express: helmet's `frameguard: false` or `xFrameOptions: false`.
//   - Django: `@xframe_options_exempt` on a view, X_FRAME_OPTIONS = 'ALLOWALL'.
//
// Another origin can then load the page in an invisible frame and have the
// user click through it as themselves. A response that is never rendered (a
// JSON API) is not exposed, which is why this is reported at medium
// confidence: the finding is the switch, the reader decides whether the
// response is a page a user acts on.
const RuleFramingOff = "APPCFG-009"

// RuleSessionFixationOff (APPCFG-010) reports Spring Security configuration
// that keeps the pre-login session id after authentication (CWE-384):
// `sessionFixation().none()`, `sessionFixation(f -> f.none())`, a method
// reference to `none`, and the Kotlin DSL `sessionFixation { none() }`. A
// session id planted in the victim's browser before they log in is then the
// id of their authenticated session.
const RuleSessionFixationOff = "APPCFG-010"

// all3 is every language the framing switch is written in.
var all3 = append(append(append([]lexctx.Lang{}, py...), js...), java...)

// lambdaOrRef matches the argument a Spring configurer takes to call one
// method on its configuration: `x -> x.m(`, `(x) -> x.m(`, `Type::m`.
func lambdaOrRef(method string) string {
	return `(?:[\w.]+\s*::\s*` + method + `\b|\(?\s*\w+\s*\)?\s*->\s*\w+\s*\.\s*` + method + `\s*\()`
}

// badFrameValue is an X-Frame-Options value that protects nothing.
const badFrameValue = `["'](?:ALLOWALL|ALLOW-FROM\s+\*|\*)["']`

var framingRules = []rule{{
	id: RuleFramingOff, cwe: "CWE-1021", severity: findings.SeverityMedium,
	confidence:  findings.ConfidenceMedium,
	message:     "Framing protection (X-Frame-Options / frame-ancestors) is switched off in source",
	description: "Clickjacking protection switched off: Spring Security frameOptions().disable(), frameOptions(f -> f.disable()), headers().disable(); X-Frame-Options set to ALLOWALL or *, or removed from the response; Content-Security-Policy frame-ancestors *; helmet frameguard: false / xFrameOptions: false; Django @xframe_options_exempt, X_FRAME_OPTIONS = 'ALLOWALL'",
	remediation: "Send X-Frame-Options: DENY (or SAMEORIGIN where the application frames its own pages) and Content-Security-Policy: frame-ancestors 'none' or a list of the origins allowed to frame the page. Spring Security: keep the default headers, or use frameOptions(f -> f.sameOrigin()). Express: keep helmet's frameguard. Django: keep XFrameOptionsMiddleware and remove @xframe_options_exempt from views a user acts on.",
	tags:        []string{"clickjacking", "headers", "spring", "express", "django", "owasp-a05"},
	patterns: []pattern{
		{langs: java, need: "frameOptions", re: regexp.MustCompile(`\bframeOptions\s*\(\s*\)\s*\.\s*disable\s*\(`)},
		{langs: java, need: "frameOptions", re: regexp.MustCompile(`\bframeOptions\s*\(\s*` + lambdaOrRef("disable"))},
		{langs: java, need: "frameOptions", re: regexp.MustCompile(`\bframeOptions\s*\{\s*disable\s*\(\s*\)`)},
		{langs: java, need: "headers", re: regexp.MustCompile(`\bheaders\s*\(\s*\)\s*\.\s*disable\s*\(`)},
		{langs: java, need: "headers", re: regexp.MustCompile(`\bheaders\s*\(\s*` + lambdaOrRef("disable"))},
		{langs: all3, need: "rame-Options|RAME-OPTIONS|rame-options", re: regexp.MustCompile(`(?i)\b\w+\s*\(\s*["']X-Frame-Options["']\s*,\s*` + badFrameValue)},
		{langs: all3, need: "rame-Options|RAME-OPTIONS|rame-options", re: regexp.MustCompile(`(?i)\b\w+\s*\[\s*["']X-Frame-Options["']\s*\]\s*=\s*` + badFrameValue)},
		{langs: all3, need: "rame-Options|RAME-OPTIONS|rame-options", re: regexp.MustCompile(`(?i)\b(?:remove|removeHeader|delete|pop)\s*\(\s*["']X-Frame-Options["']\s*\)`)},
		{langs: py, need: "rame-Options|RAME-OPTIONS|rame-options", re: regexp.MustCompile(`(?i)\bdel\s+[\w.]+\s*\[\s*["']X-Frame-Options["']\s*\]`)},
		{langs: all3, need: "frame-ancestors", re: regexp.MustCompile(`(?i)\b\w+\s*\(\s*["']Content-Security-Policy["']\s*,\s*(?:"[^"\n]*|'[^'\n]*)\bframe-ancestors\s+\*`)},
		{langs: js, need: "frameguard", near: "helmet", re: regexp.MustCompile(`\bframeguard\s*:\s*false\b`)},
		{langs: js, need: "xFrameOptions", near: "helmet", re: regexp.MustCompile(`\bxFrameOptions\s*:\s*false\b`)},
		{langs: py, need: "xframe_options_exempt", re: regexp.MustCompile(`(?m)^[ \t]*@xframe_options_exempt\b`)},
		{langs: py, need: "X_FRAME_OPTIONS", re: regexp.MustCompile(`\bX_FRAME_OPTIONS\s*=\s*` + badFrameValue)},
	},
}, {
	id: RuleSessionFixationOff, cwe: "CWE-384", severity: findings.SeverityMedium,
	message:     "Session fixation protection is switched off: the session id is kept across login",
	description: "Spring Security sessionFixation().none(), sessionFixation(f -> f.none()), a method reference to none, Kotlin sessionFixation { none() }",
	remediation: "Keep Spring Security's default (changeSessionId), or use migrateSession / newSession, so authentication issues a new session id.",
	tags:        []string{"session", "spring", "owasp-a07"},
	patterns: []pattern{
		{langs: java, need: "sessionFixation", re: regexp.MustCompile(`\bsessionFixation\s*\(\s*\)\s*\.\s*none\s*\(`)},
		{langs: java, need: "sessionFixation", re: regexp.MustCompile(`\bsessionFixation\s*\(\s*` + lambdaOrRef("none"))},
		{langs: java, need: "sessionFixation", re: regexp.MustCompile(`\bsessionFixation\s*\{\s*none\s*\(\s*\)`)},
	},
}}
