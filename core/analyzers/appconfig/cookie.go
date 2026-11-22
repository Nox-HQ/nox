package appconfig

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// Cookie flags -- APPCFG-004 (HttpOnly, CWE-1004) and APPCFG-005 (Secure,
// CWE-614).
//
// Two things are reported, and the line between them is deliberate.
//
// A flag switched OFF in writing -- `httpOnly: false`, `httponly=False`,
// `setHttpOnly(false)`, Spring's `server.servlet.session.cookie.secure:
// false`, Tomcat's `useHttpOnly="false"` -- is reported on any cookie: it is the
// developer writing the decision down, the principle HARDEN-003 already applies
// to `secure=False` in Python and `setSecure(false)` in Java (which it keeps;
// they are not reported twice).
//
// A flag OMITTED is reported only on a cookie that carries a session or a
// credential: its name or value names a session, token, auth, JWT, sid,
// login, remember-me, access or refresh. Frameworks default HttpOnly and Secure
// off for a cookie set by hand, so an omitted flag is the same exposure, but on
// a preference or a UI cookie it is no exposure at all, and reporting every
// cookie call would fire on most cookie code in existence (see HARDEN-003's
// rationale). A session middleware (express-session, cookie-session) holds the
// session by definition, and is reported when no `secure` is given.
//
// A flag passed as anything but a literal (`secure: isProd`) is a deployment
// switch, usually the right one, and is never reported. An options object
// passed by name is not read.
const (
	RuleCookieHTTPOnly = "APPCFG-004"
	RuleCookieSecure   = "APPCFG-005"
)

var cookieRules = []rule{
	{
		id: RuleCookieHTTPOnly, cwe: "CWE-1004", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
		message:     "Cookie holding a session or credential is readable by page scripts (HttpOnly not set)",
		description: "Session or credential cookie set without HttpOnly, or HttpOnly switched off in writing (httpOnly: false, httponly=False, setHttpOnly(false), useHttpOnly=\"false\", http-only: false)",
		remediation: "Set HttpOnly on every cookie that carries a session or a credential, so a script injected into the page cannot read it: Express res.cookie(name, v, { httpOnly: true }), Flask/Django set_cookie(..., httponly=True), Java cookie.setHttpOnly(true), Spring server.servlet.session.cookie.http-only: true.",
		tags:        []string{"cookie", "session", "owasp-a05"},
		patterns: []pattern{
			{langs: js, need: "httpOnly", re: regexp.MustCompile(`\bhttpOnly\s*:\s*false\b`)},
			{langs: py, need: "httponly", re: regexp.MustCompile(`\bhttponly\s*=\s*False\b`)},
			{langs: py, need: "SESSION_COOKIE_HTTPONLY", re: regexp.MustCompile(`(?m)^\s*SESSION_COOKIE_HTTPONLY\s*=\s*False\b`)},
			{langs: java, need: "HttpOnly", re: regexp.MustCompile(`\.\s*setHttpOnly\s*\(\s*false\s*\)`)},
			{langs: java, need: "httpOnly", whole: true, re: regexp.MustCompile(`\bResponseCookie\b[^;]*?\.\s*httpOnly\s*\(\s*false\s*\)`)},
		},
	},
	{
		id: RuleCookieSecure, cwe: "CWE-614", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
		message:     "Cookie holding a session or credential is sent over plain HTTP (Secure not set)",
		description: "Session or credential cookie set without Secure, a session middleware without cookie.secure, or Secure switched off in writing in JavaScript cookie options, Django/Flask settings or Spring configuration",
		remediation: "Set Secure on every cookie that carries a session or a credential: Express res.cookie(name, v, { secure: true }), express-session cookie: { secure: true }, set_cookie(..., secure=True), SESSION_COOKIE_SECURE = True, cookie.setSecure(true), Spring server.servlet.session.cookie.secure: true.",
		tags:        []string{"cookie", "session", "transport-security", "owasp-a05"},
		patterns: []pattern{
			// `secure: false` is also nodemailer's SMTP option: only a cookie's.
			{langs: js, need: "secure", near: "ookie", re: regexp.MustCompile(`\bsecure\s*:\s*false\b`)},
			{langs: py, need: "SESSION_COOKIE_SECURE", re: regexp.MustCompile(`(?m)^\s*SESSION_COOKIE_SECURE\s*=\s*False\b`)},
		},
	},
}

// authCookie reports text that names a session or a credential: a cookie's
// name, or the expression its value comes from.
var authCookie = regexp.MustCompile(`(?i)sess|token|auth|jwt|\bsid\b|_sid|sid_|login|remember|credential|bearer|access|refresh`)

var (
	jsCookieCall      = regexp.MustCompile(`\b(?:res|response|reply|ctx|resp)\s*\.\s*cookie\s*\(`)
	jsCookiesSet      = regexp.MustCompile(`\bcookies\s*(?:\(\s*\))?\s*\.\s*set\s*\(`)
	jsSessionMW       = regexp.MustCompile(`\b(?:session|cookieSession)\s*\(\s*\{`)
	pyCookieCall      = regexp.MustCompile(`\bset_cookie\s*\(`)
	javaNewCookie     = regexp.MustCompile(`\bnew\s+(?:javax\s*\.\s*servlet\s*\.\s*http\s*\.\s*|jakarta\s*\.\s*servlet\s*\.\s*http\s*\.\s*)?Cookie\s*\(`)
	javaRespCookie    = regexp.MustCompile(`\bResponseCookie\s*\.\s*from\s*\(`)
	javaAssignedTo    = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*$`)
	jsHTTPOnlyKey     = regexp.MustCompile(`\bhttpOnly\s*:`)
	jsSecureKey       = regexp.MustCompile(`\bsecure\s*:`)
	jsCookieSecureKey = regexp.MustCompile(`\bcookie\s*:\s*\{[^}]*\bsecure\s*:`)
	pyHTTPOnlyKw      = regexp.MustCompile(`\bhttponly\s*=`)
	pySecureKw        = regexp.MustCompile(`\bsecure\s*=`)
	pyKeyKw           = regexp.MustCompile(`\bkey\s*=\s*([^,)]+)`)
	pyValueKw         = regexp.MustCompile(`\bvalue\s*=\s*([^,)]+)`)
	jsNameProp        = regexp.MustCompile(`\bname\s*:\s*([^,}]+)`)
	jsValueProp       = regexp.MustCompile(`\bvalue\s*:\s*([^,}]+)`)
	defBefore         = regexp.MustCompile(`\bdef\s+$`)
)

// scanCookies reports session and credential cookies whose HttpOnly or
// Secure flag is omitted.
func scanCookies(path string, lang lexctx.Lang, content, masked []byte) []findings.Finding {
	if !bytes.Contains(content, []byte("ookie")) && !bytes.Contains(content, []byte("ession(")) {
		return nil
	}
	var out []findings.Finding
	report := func(id string, at int) {
		out = append(out, cookieFinding(id, path, lang, content, at))
	}
	switch lang {
	case lexctx.LangJavaScript:
		for _, re := range []*regexp.Regexp{jsCookieCall, jsCookiesSet} {
			for _, loc := range re.FindAllIndex(masked, -1) {
				args := callArgs(content, masked, loc[1]-1)
				name, value, opts := "", "", ""
				switch {
				case len(args) == 1 && strings.HasPrefix(strings.TrimSpace(args[0]), "{"):
					opts = args[0] // cookies().set({ name, value, httpOnly })
					name, value = firstGroup(jsNameProp, opts), firstGroup(jsValueProp, opts)
				case len(args) >= 2:
					name, value = args[0], args[1]
					if len(args) >= 3 {
						opts = args[2]
						if !strings.HasPrefix(strings.TrimSpace(opts), "{") {
							continue // options passed by name: not read
						}
					}
				default:
					continue
				}
				if clearsCookie(value) || (!authCookie.MatchString(name) && !authCookie.MatchString(value)) {
					continue
				}
				if !jsHTTPOnlyKey.MatchString(opts) {
					report(RuleCookieHTTPOnly, loc[0])
				}
				if !jsSecureKey.MatchString(opts) {
					report(RuleCookieSecure, loc[0])
				}
			}
		}
		for _, loc := range jsSessionMW.FindAllIndex(masked, -1) {
			body := spanText(content, masked, loc[1]-2)
			if !strings.Contains(body, "secret") && !strings.Contains(body, "keys") {
				continue // not express-session / cookie-session's options
			}
			if !jsCookieSecureKey.MatchString(body) {
				report(RuleCookieSecure, loc[0])
			}
		}
	case lexctx.LangPython:
		for _, loc := range pyCookieCall.FindAllIndex(masked, -1) {
			if defBefore.Match(masked[max(0, loc[0]-16):loc[0]]) {
				continue // a framework's own `def set_cookie(...)`
			}
			args := callArgs(content, masked, loc[1]-1)
			all := strings.Join(args, ",")
			name, value := firstGroup(pyKeyKw, all), firstGroup(pyValueKw, all)
			if name == "" && len(args) > 0 && !strings.Contains(args[0], "=") {
				name = args[0]
			}
			if value == "" && len(args) > 1 && !strings.Contains(args[1], "=") {
				value = args[1]
			}
			if clearsCookie(value) || (!authCookie.MatchString(name) && !authCookie.MatchString(value)) {
				continue
			}
			if !pyHTTPOnlyKw.MatchString(all) {
				report(RuleCookieHTTPOnly, loc[0])
			}
			if !pySecureKw.MatchString(all) {
				report(RuleCookieSecure, loc[0])
			}
		}
	case lexctx.LangJava, lexctx.LangKotlin:
		for _, loc := range javaNewCookie.FindAllIndex(masked, -1) {
			args := callArgs(content, masked, loc[1]-1)
			if len(args) < 2 || clearsCookie(args[1]) || (!authCookie.MatchString(args[0]) && !authCookie.MatchString(args[1])) {
				continue
			}
			// The flags are set on the variable afterwards, in the same method.
			after := string(content[loc[1]:min(len(content), loc[1]+1200)])
			v := ""
			if m := javaAssignedTo.FindSubmatch(masked[max(0, loc[0]-80):loc[0]]); m != nil {
				v = string(m[1])
			}
			if v == "" || !strings.Contains(after, v+".setHttpOnly(") {
				report(RuleCookieHTTPOnly, loc[0])
			}
			if v == "" || !strings.Contains(after, v+".setSecure(") {
				report(RuleCookieSecure, loc[0])
			}
		}
		for _, loc := range javaRespCookie.FindAllIndex(masked, -1) {
			args := callArgs(content, masked, loc[1]-1)
			if len(args) < 1 || !authCookie.MatchString(strings.Join(args, ",")) {
				continue
			}
			end := bytes.IndexByte(masked[loc[1]:], ';')
			if end < 0 {
				continue
			}
			chain := string(content[loc[1] : loc[1]+end])
			if !strings.Contains(chain, ".httpOnly(") {
				report(RuleCookieHTTPOnly, loc[0])
			}
			if !strings.Contains(chain, ".secure(") {
				report(RuleCookieSecure, loc[0])
			}
		}
	}
	return out
}

// clearsCookie reports a value that deletes the cookie rather than setting
// it: an empty string, None, null or undefined. A deletion carries no session.
func clearsCookie(value string) bool {
	switch strings.TrimSpace(value) {
	case `''`, `""`, "``", "None", "null", "undefined":
		return true
	}
	return false
}

func cookieFinding(id, path string, lang lexctx.Lang, content []byte, at int) findings.Finding {
	r := cookieRules[0]
	if id == RuleCookieSecure {
		r = cookieRules[1]
	}
	line := lexctx.LineForOffset(content, at)
	return findings.Finding{
		RuleID:     r.id,
		Severity:   r.severity,
		Confidence: findings.ConfidenceMedium,
		Message:    r.message,
		Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Metadata:   map[string]string{"cwe": r.cwe, "language": lang.String()},
	}
}

// callArgs returns a call's top-level arguments as raw text, given the offset
// of its opening parenthesis. Brackets and commas are read from the mask, so a
// comma inside a string does not split an argument.
func callArgs(content, masked []byte, open int) []string {
	end := closeParen(masked, open)
	if end < 0 {
		return nil
	}
	var out []string
	depth, start := 0, open+1
	for i := open + 1; i < end; i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, string(content[start:i]))
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(string(content[start:end])) != "" {
		out = append(out, string(content[start:end]))
	}
	return out
}

// spanText is the raw text of the bracketed span opening at open.
func spanText(content, masked []byte, open int) string {
	end := closeParen(masked, open)
	if end < 0 {
		return ""
	}
	return string(content[open:end])
}

// closeParen is the offset of the bracket closing the one at open, or -1.
func closeParen(masked []byte, open int) int {
	depth := 0
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Spring and Tomcat configuration: a session cookie flag switched off.
var (
	propsCookieOff = regexp.MustCompile(`(?m)^\s*server\.servlet\.session\.cookie\.(secure|http-only)\s*[=:]\s*false\b`)
	yamlFlagOff    = regexp.MustCompile(`(?m)^(\s*)(secure|http-only)\s*:\s*false\b`)
	tomcatHTTPOnly = regexp.MustCompile(`\buseHttpOnly\s*=\s*["']false["']`)
)

// scanCookieConfig reads Spring properties/YAML and Tomcat context.xml.
func scanCookieConfig(path string, content []byte) []findings.Finding {
	if !bytes.Contains(content, []byte("false")) {
		return nil
	}
	base := strings.ToLower(path)
	var out []findings.Finding
	add := func(flag string, at int) {
		id := RuleCookieSecure
		if flag == "http-only" || flag == "httponly" {
			id = RuleCookieHTTPOnly
		}
		out = append(out, cookieFinding(id, path, lexctx.LangUnknown, content, at))
	}
	switch {
	case strings.HasSuffix(base, ".properties"):
		for _, m := range propsCookieOff.FindAllSubmatchIndex(content, -1) {
			add(string(content[m[2]:m[3]]), m[0])
		}
	case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		for _, m := range yamlFlagOff.FindAllSubmatchIndex(content, -1) {
			// Only under a `cookie:` key: Spring's server.servlet.session.cookie.
			before := content[max(0, m[0]-200):m[0]]
			if !bytes.Contains(before, []byte("cookie:")) {
				continue
			}
			add(string(content[m[4]:m[5]]), m[0])
		}
	case strings.HasSuffix(base, ".xml"):
		for _, m := range tomcatHTTPOnly.FindAllIndex(content, -1) {
			add("httponly", m[0])
		}
	}
	return out
}
