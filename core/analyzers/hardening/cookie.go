package hardening

import (
	"bytes"
	"regexp"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
)

// Insecure cookie — HARDEN-003.
//
// A cookie set with `secure=False` is sent over plain HTTP whenever the browser
// makes a plain-HTTP request to the site, where anyone on the path reads it. For
// a session or authentication cookie that is account takeover. CWE-614.
//
// WHAT IS REPORTED. Only the explicit statement: a Python `set_cookie` or
// `set_signed_cookie` call (Flask/Werkzeug, Django, Starlette, FastAPI) passed
// the literal keyword `secure=False`. That is the developer writing down the
// decision, and it is reported wherever it is written.
//
// WHAT IS NOT. An omitted flag. Werkzeug and Django default `secure` to False,
// so an omitted flag is insecure in the same way, but whether it matters is
// decided by deployment -- a framework-level setting such as
// SESSION_COOKIE_SECURE, a proxy that rewrites Set-Cookie, HSTS -- none of
// which a file shows. Reporting every call without the flag would fire on
// most cookie code in existence and be suppressed in a week. `secure=` bound
// to anything but the literal (`secure=not settings.DEBUG`) is not reported
// either: that is a deployment switch, usually the right one.
//
// Java: `cookie.setSecure(false)` on a javax/jakarta servlet Cookie, and
// Spring's `ResponseCookie.from(…).secure(false)`. The same rule: only the
// literal false, only as written.
//
// Test paths are skipped, as for HARDEN-001: tests set cookies over plain
// HTTP to local servers on purpose.
const ruleInsecureCookie = "HARDEN-003"

var (
	cookieCallRe         = regexp.MustCompile(`\bset(?:_signed)?_cookie\s*\(`)
	secureFalseRe        = regexp.MustCompile(`\bsecure\s*=\s*False\b`)
	defBefore            = regexp.MustCompile(`\bdef\s+$`)
	javaSetSecure        = regexp.MustCompile(`\.\s*setSecure\s*\(\s*false\s*\)`)
	javaRespCookieSecure = regexp.MustCompile(`\bResponseCookie\b[^;]*?\.\s*secure\s*\(\s*false\s*\)`)
)

func insecureCookieRule() *rules.Rule {
	return &rules.Rule{
		ID:          ruleInsecureCookie,
		Version:     "1.0",
		Description: "Cookie set with the Secure flag explicitly disabled (Python secure=False, Java setSecure(false))",
		// Medium: the cookie's contents decide the impact -- a session cookie
		// sent in the clear is takeover, a UI preference is nothing -- and
		// the call does not say which.
		Severity: findings.SeverityMedium,
		// High: the keyword and the literal are both in the source.
		Confidence: findings.ConfidenceHigh,
		Tags:       []string{"cookie", "transport-security", "owasp-a05"},
		Remediation: "This cookie is sent over plain HTTP, where anyone on the network path can read it; for a session or authentication cookie that is account takeover. " +
			"Remove `secure=False` and pass `secure=True`, together with `httponly=True` and `samesite=\"Lax\"` (or \"Strict\"). " +
			"If plain HTTP is needed only in local development, derive the flag from configuration (`secure=not app.debug`, or Django's SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE settings) rather than hard-coding False. " +
			"If this cookie genuinely carries nothing sensitive, suppress the finding with a nox:ignore comment recording that.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/614.html",
			"https://owasp.org/www-community/controls/SecureCookieAttribute",
		},
		Metadata: map[string]string{"cwe": "CWE-614"},
	}
}

// scanPythonCookies reports set_cookie calls passed secure=False in one Python
// file. Comments and strings are masked first, so the text in a docstring or a
// commented-out call is not code.
func scanPythonCookies(path string, content []byte) []findings.Finding {
	if !bytes.Contains(content, []byte("_cookie")) {
		return nil
	}
	masked := lexctx.MaskNonCode(lexctx.LangPython, content)
	var out []findings.Finding
	for _, loc := range cookieCallRe.FindAllIndex(masked, -1) {
		if defBefore.Match(masked[max(0, loc[0]-16):loc[0]]) {
			// `def set_cookie(self, ..., secure=False)`: a framework's own
			// signature, where secure=False is a parameter default, not a
			// cookie being set. Found as 36 of 41 GitHub hits before this.
			continue
		}
		open := loc[1] - 1
		args := masked[open:closingParen(masked, open)]
		m := topLevelMatch(secureFalseRe, args)
		if m < 0 {
			continue
		}
		line := lexctx.LineForOffset(content, open+m)
		out = append(out, findings.Finding{
			RuleID:     ruleInsecureCookie,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceHigh,
			Message:    "Cookie set with secure=False is sent over plain HTTP",
			Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
			Metadata:   map[string]string{"cwe": "CWE-614", "language": "python"},
		})
	}
	return out
}

// closingParen returns the offset just past the bracket matching the one at
// open, or the end of b.
func closingParen(b []byte, open int) int {
	depth := 0
	for i := open; i < len(b); i++ {
		switch b[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(b)
}

// topLevelMatch returns the offset of re's first match in args that is a
// keyword of THIS call -- depth one inside its parentheses -- or -1, so a
// nested call's `secure=False` is not read as the cookie's.
func topLevelMatch(re *regexp.Regexp, args []byte) int {
	for _, loc := range re.FindAllIndex(args, -1) {
		depth := 0
		for _, c := range args[:loc[0]] {
			switch c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			}
		}
		if depth == 1 {
			return loc[0]
		}
	}
	return -1
}

// scanJavaCookies reports a servlet Cookie's setSecure(false) and Spring's
// ResponseCookie secure(false) in one Java file.
func scanJavaCookies(path string, content []byte) []findings.Finding {
	if !bytes.Contains(content, []byte("ecure")) {
		return nil
	}
	masked := lexctx.MaskNonCode(lexctx.LangJava, content)
	var out []findings.Finding
	for _, re := range []*regexp.Regexp{javaSetSecure, javaRespCookieSecure} {
		for _, loc := range re.FindAllIndex(masked, -1) {
			line := lexctx.LineForOffset(content, loc[1]-1)
			out = append(out, findings.Finding{
				RuleID:     ruleInsecureCookie,
				Severity:   findings.SeverityMedium,
				Confidence: findings.ConfidenceHigh,
				Message:    "Cookie with its Secure flag set to false is sent over plain HTTP",
				Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
				Metadata:   map[string]string{"cwe": "CWE-614", "language": "java"},
			})
		}
	}
	return out
}
