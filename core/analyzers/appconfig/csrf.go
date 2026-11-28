package appconfig

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// RuleCSRFDisabled (APPCFG-008) reports configuration that switches CSRF
// protection off, or off for some routes (CWE-352), where the developer writes
// the decision down:
//
//   - Spring Security: `.csrf().disable()`, `.csrf(c -> c.disable())`,
//     `.csrf(AbstractHttpConfigurer::disable)`,
//     `.csrf(c -> c.ignoringRequestMatchers(...))`, and the Kotlin DSL
//     `csrf { disable() }`.
//   - Django: `@csrf_exempt`, `csrf_exempt(view)` in a URL pattern, a Django
//     REST framework authentication class whose `enforce_csrf` does nothing,
//     and a settings module whose MIDDLEWARE keeps SessionMiddleware but not
//     CsrfViewMiddleware (commented out or never listed).
//   - Flask-WTF: `@csrf.exempt` and `WTF_CSRF_ENABLED = False`.
//
// A browser that holds the user's session cookie then submits a forged form
// or request to those routes as the user. An API that authenticates every
// request with a bearer token rather than a cookie is not exposed, which is
// why this is reported at medium confidence: the finding is the switch, the
// reader decides whether the routes are reached with a cookie.
const RuleCSRFDisabled = "APPCFG-008"

var csrfRules = []rule{{
	id: RuleCSRFDisabled, cwe: "CWE-352", severity: findings.SeverityMedium,
	confidence:  findings.ConfidenceMedium,
	message:     "CSRF protection is switched off in source",
	description: "CSRF protection disabled or exempted for routes: Spring Security csrf().disable(), csrf(c -> c.disable()), csrf(AbstractHttpConfigurer::disable), ignoringRequestMatchers / ignoringAntMatchers; Django @csrf_exempt, csrf_exempt(view), CsrfViewMiddleware removed from MIDDLEWARE, a DRF enforce_csrf that does nothing; Flask-WTF @csrf.exempt, WTF_CSRF_ENABLED = False",
	remediation: "Keep CSRF protection on for every route a browser reaches with a session cookie; exempt only endpoints authenticated by a bearer token or signature, and say so beside the exemption. Django: remove @csrf_exempt and send the token ({% csrf_token %}, or the X-CSRFToken header from the csrftoken cookie), keep django.middleware.csrf.CsrfViewMiddleware in MIDDLEWARE. Flask-WTF: remove @csrf.exempt and keep WTF_CSRF_ENABLED on.",
	tags:        []string{"csrf", "spring", "django", "flask", "owasp-a01"},
	patterns: []pattern{
		{langs: java, need: "csrf", re: regexp.MustCompile(`\.\s*csrf\s*\(\s*\)\s*\.\s*(?:disable|ignoring(?:RequestMatchers|AntMatchers))\s*\(`)},
		{langs: java, need: "csrf", re: regexp.MustCompile(`\.\s*csrf\s*\(\s*(?:[\w.]+\s*::\s*disable|\(?\s*\w+\s*\)?\s*->\s*\w+\s*\.\s*(?:disable|ignoring(?:RequestMatchers|AntMatchers))\s*\()`)},
		{langs: java, need: "csrf", re: regexp.MustCompile(`\bcsrf\s*\{\s*disable\s*\(\s*\)`)},
		{langs: py, need: "csrf_exempt", re: regexp.MustCompile(`\bcsrf_exempt\s*\(\s*[A-Za-z_][\w.]*`)},
		{langs: py, need: "enforce_csrf", re: regexp.MustCompile(`(?m)\bdef\s+enforce_csrf\s*\([^)]*\)\s*(?:->\s*\w+\s*)?:[ \t]*(?:#[^\n]*)?\n?[ \t]*(?:return(?:[ \t]+None)?[ \t]*(?:#[^\n]*)?$|pass\b)`)},
		{langs: py, need: "exempt", re: regexp.MustCompile(`(?mi)^[ \t]*@\w*csrf\w*\.exempt\b`)},
		{langs: py, need: "WTF_CSRF_ENABLED", re: regexp.MustCompile(`(?:\[\s*['"]WTF_CSRF_ENABLED['"]\s*\]|\bWTF_CSRF_ENABLED)\s*=\s*False\b`)},
	},
}}

// djangoMiddlewareRe finds a settings module's MIDDLEWARE list.
var djangoMiddlewareRe = regexp.MustCompile(`(?m)^MIDDLEWARE(?:_CLASSES)?\s*=\s*[\[(]`)

// scanDjangoCSRF reports a Django settings module whose MIDDLEWARE keeps
// sessions but not CsrfViewMiddleware: at the commented-out entry when there
// is one, at MIDDLEWARE otherwise. Absence is not a pattern, so it is read
// here: the list is taken with comments blanked, so an entry commented out is
// an entry removed.
func scanDjangoCSRF(path string, lang lexctx.Lang, content []byte) []findings.Finding {
	if lang != lexctx.LangPython || !isDjangoSettings(path) {
		return nil
	}
	loc := djangoMiddlewareRe.FindIndex(content)
	if loc == nil {
		return nil
	}
	code := commentsBlanked(lang, content)
	end := strings.IndexAny(code[loc[1]:], "])")
	if end < 0 {
		return nil
	}
	end += loc[1]
	list := code[loc[1]:end]
	if !strings.Contains(list, "SessionMiddleware") || strings.Contains(list, "CsrfViewMiddleware") {
		return nil
	}
	at := loc[0]
	if i := bytes.Index(content[loc[1]:end], []byte("CsrfViewMiddleware")); i >= 0 {
		at = loc[1] + i
	}
	line := lexctx.LineForOffset(content, at)
	return []findings.Finding{{
		RuleID:     RuleCSRFDisabled,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Message:    "CSRF protection is switched off in source: Django MIDDLEWARE keeps sessions but not CsrfViewMiddleware",
		Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Metadata:   map[string]string{"cwe": "CWE-352", "language": lang.String()},
	}}
}

// commentsBlanked returns raw with every comment byte blanked, offsets kept.
func commentsBlanked(lang lexctx.Lang, raw []byte) string {
	out := make([]byte, len(raw))
	copy(out, raw)
	for _, r := range lexctx.Classify(lang, raw) {
		if r.Kind != lexctx.KindComment {
			continue
		}
		for i := r.Start; i < r.End; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// csrfExemptRe is Django's view decorator.
var csrfExemptRe = regexp.MustCompile(`(?m)^([ \t]*)@csrf_exempt\b`)

// safeMethodOnlyRe: the view serves only methods a forged cross-site request
// cannot use to change anything (Django's own decorators, or a body that
// rejects every other method).
var safeMethodOnlyRe = regexp.MustCompile(`@require_GET\b|@require_safe\b|@require_http_methods\s*\(\s*\[\s*['"](?:GET|HEAD)['"]\s*(?:,\s*['"](?:GET|HEAD|OPTIONS)['"]\s*)*\]\s*\)|\bif\s+request\.method\s*!=\s*['"]GET['"]\s*:\s*\n\s*return\b`)

// headerAuthRe: the view authenticates the caller by a header, a key or a
// signature, which a cross-site page cannot make a browser send.
var headerAuthRe = regexp.MustCompile(`(?i)HTTP_AUTHORIZATION|HTTP_X_[A-Z_]*(?:KEY|TOKEN|SIGNATURE)|headers\s*(?:\.get\s*\(|\[)\s*['"](?:authorization|x-[\w-]*(?:key|token|signature))['"]|\bapi_?key|\bBearer\b|token_required|verify_signature|compare_digest|\bhmac\b|webhook`)

// changesStateRe: the view acts on what was submitted or writes a record.
// CSRF forges a request; a view that only reads gives the forger nothing, as
// a cross-site page cannot read the response.
var changesStateRe = regexp.MustCompile(`\brequest\s*\.\s*(?:POST|body|data|FILES)\b|\.\s*(?:save|create|delete|update|update_or_create|get_or_create|bulk_create|set_password|add|remove)\s*\(`)

// scanCSRFExempt reports @csrf_exempt on a Django view that a browser can
// drive with its session cookie to change something: one that accepts an
// unsafe method, acts on what was submitted or writes a record, and does not
// authenticate the caller by a header, a key or a signature.
func scanCSRFExempt(path string, lang lexctx.Lang, content []byte) []findings.Finding {
	if lang != lexctx.LangPython || !bytes.Contains(content, []byte("csrf_exempt")) {
		return nil
	}
	code := commentsBlanked(lang, content)
	var out []findings.Finding
	for _, m := range csrfExemptRe.FindAllStringSubmatchIndex(code, -1) {
		view := decoratedFunction(code, m[0], m[3]-m[2])
		if safeMethodOnlyRe.MatchString(view) || headerAuthRe.MatchString(view) || !changesStateRe.MatchString(view) {
			continue
		}
		line := lexctx.LineForOffset(content, m[1]-len("csrf_exempt"))
		out = append(out, findings.Finding{
			RuleID:     RuleCSRFDisabled,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceMedium,
			Message:    "CSRF protection is switched off in source: @csrf_exempt on a view that changes state on a submitted request and authenticates no header, key or signature",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-352", "language": lang.String()},
		})
	}
	return out
}

// decoratedFunction returns the text from the decorator at start through the
// end of the function it decorates: its other decorators, the def line, and
// every following line indented deeper than the def (or blank).
func decoratedFunction(code string, start, indent int) string {
	lines := strings.SplitAfter(code[start:], "\n")
	var b strings.Builder
	defSeen := false
	for _, l := range lines {
		t := strings.TrimLeft(l, " \t")
		depth := len(l) - len(t)
		if !defSeen {
			b.WriteString(l)
			if strings.HasPrefix(t, "def ") || strings.HasPrefix(t, "async def ") {
				defSeen = true
			}
			continue
		}
		if strings.TrimSpace(l) != "" && depth <= indent {
			break
		}
		b.WriteString(l)
	}
	return b.String()
}
