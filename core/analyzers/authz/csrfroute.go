package authz

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// AUTHN-004, THE PROPOSITION.
//
//	A POST route is reached with the
//	session cookie -- Flask-Login or Flask's session, express-session or
//	cookie-session -- in an application that has no CSRF protection anywhere:
//	no CSRF library, no token check, and a session cookie not set SameSite.
//	A page on another site can submit that request with the user's cookie.
//
// Only POST: an HTML form sends GET or POST, and a cross-site PUT, PATCH or
// DELETE needs a CORS preflight the server would have to grant. A GET that
// changes state is a different defect, reported on its own.
//
// Flask and Express are the frameworks where this is the default: neither
// ships CSRF protection, so the application must add it. Django, Spring
// Security, Rails, Laravel and ASP.NET ship it on, and switching it off is
// APPCFG-008's claim, not this one.
//
// "Reached with the session cookie": the route's authentication is session
// login (@login_required from Flask-Login, a middleware named for the session
// or login), or its handler reads the session or the logged-in user. A route
// authenticated by a token, a key or a JWT decorator is not: a cross-site page
// cannot make the browser send a header.
//
// A handler that reads only a JSON body is not a target: Flask's get_json()
// refuses any other content type, an Express app with no form-body parser
// leaves req.body empty for a form, and a cross-site page cannot send JSON
// without a CORS preflight the server never grants. A route that reads no
// body at all (a logout, a delete by id) still is.
//
// COUNTEREXAMPLES, repository-wide for the language: any CSRF library or check
// (Flask-WTF CSRFProtect or FlaskForm, which carries a token by default,
// SeaSurf, csurf, csrf-csrf, lusca, a "csrf" token read anywhere), or the
// session cookie set SameSite=Lax or Strict, which keeps a cross-site POST
// from carrying it.

// CSRFRouteRuleID is AUTHN-004.
const CSRFRouteRuleID = "AUTHN-004"

// csrfDefenceRe is CSRF protection of any kind, in code.
var csrfDefenceRe = regexp.MustCompile(`(?i)csrf|xsrf|\bFlaskForm\b|\bSeaSurf\b|\blusca\b|\bSESSION_COOKIE_SAMESITE\s*=\s*['"](?:lax|strict)['"]|\bsameSite\s*:\s*(?:['"](?:lax|strict)['"]|true)|samesite\s*=\s*['"](?:lax|strict)['"]`)

// pyCookieSessionRe and jsCookieSessionRe: the application keeps a session in
// a cookie.
var (
	pyCookieSessionRe = regexp.MustCompile(`\bflask_login\b|\bfrom\s+flask\s+import\b[^\n]*\bsession\b|\bflask\.session\b`)
	jsCookieSessionRe = regexp.MustCompile(`['"](?:express-session|cookie-session)['"]`)
)

// sessionAuthRe: a route's authentication, or its handler, uses the session.
var sessionAuthRe = regexp.MustCompile(`\blogin_required\b|\bcurrent_user\b|\bsession\s*(?:\[|\.\s*get\s*\()|\breq\s*\.\s*session\b|\breq\s*\.\s*user\b|\breq\s*\.\s*isAuthenticated\s*\(|\bisLoggedIn\b|\bensureLoggedIn\b|\bensureAuthenticated\b`)

// tokenAuthRe: the route authenticates by something a cross-site page cannot
// make a browser send.
var tokenAuthRe = regexp.MustCompile(`(?i)jwt|bearer|token_required|api_?key|authorization|x-api|hmac|signature`)

// csrfDefences records, per language, whether the repository defends against
// CSRF and whether it keeps a cookie session at all.
type csrfDefences struct {
	pyDefended, jsDefended bool
	pySession, jsSession   bool
	// jsFormBodies: some Express code parses form bodies, so req.body can
	// hold what a cross-site form submits.
	jsFormBodies bool
}

// jsFormBodyRe is a parser of form or multipart bodies.
var jsFormBodyRe = regexp.MustCompile(`\burlencoded\s*\(|['"](?:multer|formidable|busboy|express-fileupload|connect-multiparty)['"]`)

// pyJSONReadRe, pyFormReadRe and jsBodyReadRe decide whether a handler reads
// only a JSON body.
var (
	pyJSONReadRe = regexp.MustCompile(`\brequest\s*\.\s*(?:get_json\s*\(|json\b)`)
	pyFormReadRe = regexp.MustCompile(`\brequest\s*\.\s*(?:form|values|files)\b`)
	jsBodyReadRe = regexp.MustCompile(`\breq\s*\.\s*body\b`)
)

// jsonOnly reports whether v's handler takes its input only from a JSON body.
func jsonOnly(v routeView, d csrfDefences) bool {
	if v.framework == "flask" {
		return pyJSONReadRe.MatchString(v.handler) && !pyFormReadRe.MatchString(v.handler)
	}
	return !d.jsFormBodies && jsBodyReadRe.MatchString(v.handler)
}

func (d *csrfDefences) read(py bool, code string) {
	defended := csrfDefenceRe.MatchString(code)
	if py {
		d.pyDefended = d.pyDefended || defended
		d.pySession = d.pySession || pyCookieSessionRe.MatchString(code)
		return
	}
	d.jsDefended = d.jsDefended || defended
	d.jsSession = d.jsSession || jsCookieSessionRe.MatchString(code)
	d.jsFormBodies = d.jsFormBodies || jsFormBodyRe.MatchString(code)
}

type csrfHit struct {
	route Route
}

// unprotectedSessionRoute reports whether v meets AUTHN-004's proposition.
func unprotectedSessionRoute(v routeView, d csrfDefences) bool {
	r := v.route
	if r.Method != "POST" {
		return false
	}
	flask := v.framework == "flask"
	express := r.Reader == ReaderExpress
	switch {
	case flask && (!d.pySession || d.pyDefended):
		return false
	case express && (!d.jsSession || d.jsDefended):
		return false
	case !flask && !express:
		return false
	}
	if nonProductionPath(r.FilePath) || v.loopbackOnly || isWebhookSegment(pathSegments(r.Path)) || jsonOnly(v, d) {
		return false
	}
	// A login or sign-up writes the session; it is not reached with one.
	// Forging it (login CSRF) is a different and weaker defect.
	tail := pathSegments(r.Path)
	if len(tail) > 2 {
		tail = tail[len(tail)-2:]
	}
	if anySegment(tail, credentialSegments) || issuing(tail) {
		return false
	}
	via := r.Authn + " " + v.chain + " " + v.handler
	return sessionAuthRe.MatchString(via) && !tokenAuthRe.MatchString(r.Authn+" "+v.chain)
}

// csrfRouteHits runs AUTHN-004 over the route views, one hit per route.
func csrfRouteHits(views []routeView, d csrfDefences) []csrfHit {
	var out []csrfHit
	seen := map[string]bool{}
	for _, v := range views {
		key := fmt.Sprintf("%s:%d:%s %s", v.route.FilePath, v.route.Line, v.route.Method, v.route.Path)
		if !seen[key] && unprotectedSessionRoute(v, d) {
			seen[key] = true
			out = append(out, csrfHit{route: v.route})
		}
	}
	return out
}

func buildCSRFRouteFinding(h csrfHit) findings.Finding {
	route := strings.TrimSpace(h.route.Method + " " + h.route.Path)
	return findings.Finding{
		RuleID:     CSRFRouteRuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: h.route.FilePath, StartLine: h.route.Line, EndLine: h.route.Line},
		Message: fmt.Sprintf("%s is authenticated by the session cookie, and the application has no CSRF protection: no CSRF library or token check, and a session cookie not set SameSite. A page on another site can submit it with the user's cookie (CWE-352).",
			route),
		Metadata: map[string]string{"cwe": "CWE-352", "route": route},
	}
}
