package authz

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// A third claim is made over the same route inventory.
//
// AUTHN-002, THE PROPOSITION.
//
//	An unauthenticated route that checks a credential -- a login, an OTP or
//	second-factor step, or a password reset confirmed with a token -- has
//	nothing in front of it or inside it that limits how often a caller may
//	try: no rate limiter or throttle on the route, its router or the
//	application, and no attempt counting or lockout in the handler or the
//	functions it calls.
//
// A credential route is named so by the end of its path (login, signin,
// authenticate, otp, mfa, 2fa, a reset confirmed by token) or shows it in its
// handler (bcrypt.compare, check_password, authenticate(),
// passwordEncoder.matches). A route behind authentication middleware is not
// one: re-entering a password to change it needs a session first.
//
// Spring Security's own login is a credential route with no controller:
// formLogin() and httpBasic() install it, and Spring Security counts no
// failed attempts unless the application does. Each is reported where it is
// configured, unless the repository counts attempts or limits requests
// anywhere in its JVM code.
//
// COUNTEREXAMPLES. A limiter or throttle on the route chain or in the handler
// (express-rate-limit, @nestjs/throttler, slowapi, Flask-Limiter,
// django-ratelimit, Bucket4j, Resilience4j), attempt counting or a lockout
// (failed attempts, locked until, max attempts), a CAPTCHA; and, for the whole
// repository, a limiter applied to every request (app.use(limiter), a
// globally registered @fastify/rate-limit, ThrottlerGuard as APP_GUARD,
// django-axes, DRF DEFAULT_THROTTLE_CLASSES, Flask-Limiter default_limits).
//
// WHAT IT CANNOT SEE: a limit enforced by a reverse proxy, gateway or WAF.
// The message says so, and the confirming test is the one an attacker runs.
//
// WHERE IT IS REPORTED: at the route registration, or at the view a Django
// URL pattern names, where the limiting decorator belongs.

// BruteForceRuleID is AUTHN-002.
const BruteForceRuleID = "AUTHN-002"

// UnthrottledIssueRuleID is AUTHN-003: the same proposition over the routes
// that create something for an anonymous caller instead of checking a
// credential -- an account, a password reset message, a one-time code. No
// credential is guessed there; each request allocates a record or sends a
// message, so an unthrottled one is CWE-770, mass account creation and
// e-mail or SMS flooding.
const UnthrottledIssueRuleID = "AUTHN-003"

// issueSegments name a route that creates an account or sends a reset
// message by its path.
var issueSegments = setOf(
	"register", "registration", "signup", "sign-up", "sign_up", "join",
	"forgot", "forgot-password", "forgot_password", "forgotpassword", "password-reset-request", "reset-request", "request-reset",
	"resend", "resend-verification", "resend-code", "resend-otp",
)

// issueStepSegments mark the step of a reset or a one-time code that sends
// it rather than consumes it.
var issueStepSegments = setOf("request", "issue", "send", "resend", "start")

// otpSegments name a one-time code.
var otpSegments = setOf("otp", "mfa", "2fa", "totp", "code")

// limiterRe is attempt limiting on a route chain or in a handler.
var limiterRe = regexp.MustCompile(`(?i)rate[_-]?limit|ratelimit|throttl|\w*limiter\b|slow[_-]?down|express[_-]?brute|\bbrute\w*|lock[_-]?out|locked[_-]?until|account[_-]?locked|failed[_-]?(?:login[_-]?)?attempts?|(?:login|auth|signin|password)[_-]?attempts?|max[_-]?attempts|attempt[_-]?count|captcha|turnstile|bucket4j|@RateLimiter\b|\baxes\b`)

// globalLimiterRe is attempt limiting applied to every request of the
// application, wherever it is written.
var globalLimiterRe = regexp.MustCompile(`(?i)\.use\(\s*(?:['"]/['"]\s*,\s*)?\w*(?:rate[_-]?limit|limiter|throttl|brute|slow[_-]?down)\w*\s*[(),]` +
	`|\.register\(\s*(?:\w*rate[_-]?limit\w*|require\(\s*['"]@fastify/rate-limit['"]\s*\)|import\(\s*['"]@fastify/rate-limit['"]\s*\))` +
	`|provide\s*:\s*APP_GUARD\s*,\s*useClass\s*:\s*\w*Throttler\w*` +
	`|useGlobalGuards\([^)]*Throttler` +
	`|['"]axes['"]|\bAxesMiddleware\b|\bAxesBackend\b|\bAxesStandaloneBackend\b` +
	`|\bDEFAULT_THROTTLE_CLASSES\b|\bdefault_limits\s*=|\bSlowAPIMiddleware\b|\bRatelimitMiddleware\b`)

// credentialSegments name a route that checks a credential by its path.
var credentialSegments = setOf(
	"login", "signin", "sign-in", "sign_in", "logon", "log-in", "authenticate", "authentication",
	"otp", "verify-otp", "verify_otp", "mfa", "2fa", "totp", "two-factor", "two_factor", "verify-2fa", "verify-mfa",
)

// resetSegments name a password reset; it checks a credential when it is the
// step that consumes the token.
var resetSegments = setOf("reset", "reset-password", "reset_password", "password-reset", "password_reset", "resetpassword")

// resetConfirmSegments mark the reset step that consumes the token.
var resetConfirmSegments = setOf("confirm", "complete", "finish", "set", "new", "verify")

// principalReadRe is a handler reading the authenticated caller.
var principalReadRe = regexp.MustCompile(`\b(?:req|request|ctx|c)\s*\??\.\s*(?:user|auth|currentUser|principal|session\s*\.\s*user(?:Id)?)\b|\bcurrent_user\b|\bg\s*\.\s*user\b|\bgetServerSession\s*\(|@AuthenticationPrincipal|\bSecurityContextHolder\b`)

// passwordCheckRe is a handler comparing a submitted password with a stored one.
var passwordCheckRe = regexp.MustCompile(`\bbcrypt(?:js)?\s*\.\s*(?:compare|compareSync|checkpw)\s*\(|\bargon2\s*\.\s*verify\s*\(|\bcheck_password\s*\(|\bcheck_password_hash\s*\(|\bverify_password\s*\(|\bverifyPassword\s*\(|\bcomparePassword\s*\(|\bcheckPassword\s*\(|\bpwd_context\s*\.\s*verify\s*\(|\bpasswordEncoder\s*\.\s*matches\s*\(|\bauthenticate\s*\(\s*(?:request\s*,|username\s*=)`)

// credentialRoute reports whether r checks a credential, what kind, and
// whether its path says so.
func credentialRoute(v routeView) (kind string, byPath, ok bool) {
	r := v.route
	switch r.Method {
	case "GET", "HEAD", "OPTIONS", "DELETE":
		return "", false, false
	}
	segs := pathSegments(r.Path)
	// The action is named at the end of the path: /admin/login and
	// /login/auth log in, /sys/user/login/setting/userEdit edits a setting.
	tail := segs
	if len(tail) > 2 {
		tail = tail[len(tail)-2:]
	}
	if issuing(tail) {
		return "", false, false
	}
	for _, s := range tail {
		if credentialSegments[s] {
			return "a credential check", true, true
		}
	}
	if anySegment(tail, resetSegments) && (hasPathParam(r.Path) || anySegment(tail, resetConfirmSegments) && !djangoResetDone(v)) {
		return "a password reset token check", true, true
	}
	// NestJS hands the reader a handler together with every service class it
	// calls, so a login's password check would be read into every route of
	// the controller: there the path alone names a credential route.
	if v.known && v.framework != "nestjs" && passwordCheckRe.MatchString(v.handler) {
		return "a password check", false, true
	}
	return "", false, false
}

// issuing reports whether a path tail names a route that creates an account
// or sends a reset message or one-time code (AUTHN-003's routes).
func issuing(tail []string) bool {
	if anySegment(tail, issueSegments) {
		return true
	}
	return anySegment(tail, issueStepSegments) && (anySegment(tail, resetSegments) || anySegment(tail, otpSegments))
}

// anySegment reports whether one of segs is in set.
func anySegment(segs []string, set map[string]bool) bool {
	for _, s := range segs {
		if set[s] {
			return true
		}
	}
	return false
}

// djangoResetDone: Django names the page shown after a reset
// "password_reset_complete"; it consumes no token.
func djangoResetDone(v routeView) bool {
	segs := pathSegments(v.route.Path)
	return v.route.Reader == ReaderDjango && len(segs) > 0 && segs[len(segs)-1] == "complete"
}

// issueRoute reports whether r creates an account or sends a reset message
// or one-time code, and what it does.
func issueRoute(v routeView) (string, bool) {
	switch v.route.Method {
	case "GET", "HEAD", "OPTIONS", "DELETE":
		return "", false
	}
	segs := pathSegments(v.route.Path)
	if len(segs) > 2 {
		segs = segs[len(segs)-2:]
	}
	if !issuing(segs) {
		return "", false
	}
	switch {
	case anySegment(segs, setOf("register", "registration", "signup", "sign-up", "sign_up", "join")):
		return "creates an account", true
	case anySegment(segs, otpSegments):
		return "sends a one-time code", true
	default:
		return "sends a password reset or verification message", true
	}
}

type bruteForceHit struct {
	rule, file, route, kind string
	line                    int
}

// unlimitedCredentialRoute reports whether v meets the proposition of
// AUTHN-002 (a credential check) or AUTHN-003 (an account or a message issued).
func unlimitedCredentialRoute(v routeView, globalLimiter bool) (bruteForceHit, bool) {
	r := v.route
	if globalLimiter || r.Authz != "" || nonProductionPath(r.FilePath) || v.loopbackOnly {
		return bruteForceHit{}, false
	}
	rule := BruteForceRuleID
	kind, byPath, ok := credentialRoute(v)
	if !ok {
		if kind, ok = issueRoute(v); !ok {
			return bruteForceHit{}, false
		}
		rule, byPath = UnthrottledIssueRuleID, true
	}
	// An inline check (a 401 answer) is what a login handler does to a wrong
	// password, so it does not make the route authenticated. Middleware does;
	// so does a handler not named for logging in that reads the caller: it is
	// re-entering a password to change it, which needs a session first.
	inline := strings.HasPrefix(r.Authn, "an inline")
	if r.Authn != "" && !inline || inline && !byPath && principalReadRe.MatchString(v.handler) {
		return bruteForceHit{}, false
	}
	if limiterRe.MatchString(v.chain) || limiterRe.MatchString(v.handler) {
		return bruteForceHit{}, false
	}
	h := bruteForceHit{rule: rule, file: r.FilePath, line: r.Line, route: strings.TrimSpace(r.Method + " " + r.Path), kind: kind}
	if v.defFile != "" {
		h.file, h.line = v.defFile, v.defLine
	}
	return h, true
}

// bruteForceHits runs AUTHN-002 over the route views, one hit per location.
func bruteForceHits(views []routeView, globalLimiter bool) []bruteForceHit {
	var out []bruteForceHit
	seen := map[string]bool{}
	for _, v := range views {
		h, ok := unlimitedCredentialRoute(v, globalLimiter)
		key := fmt.Sprintf("%s:%d", h.file, h.line)
		if ok && !seen[key] {
			seen[key] = true
			out = append(out, h)
		}
	}
	return out
}

// springLoginRe is Spring Security installing its own login: form login or
// HTTP Basic, in the lambda DSL or the chained one.
var springLoginRe = regexp.MustCompile(`\.\s*(formLogin|httpBasic)\s*\(`)

// springDisabledRe: the configurer the match opened is switched off.
var springDisabledRe = regexp.MustCompile(`^\s*(?:\)\s*\.\s*disable\s*\(|AbstractHttpConfigurer\s*::\s*disable|\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)\s*\))`)

// springLogins reports Spring Security logins in files, unless the
// repository's JVM code counts attempts or limits requests anywhere.
func springLogins(files []*jvmFile) []bruteForceHit {
	for _, f := range files {
		if limiterRe.MatchString(f.sans) {
			return nil
		}
	}
	var out []bruteForceHit
	for _, f := range files {
		if nonProductionPath(f.path) {
			continue
		}
		for _, m := range springLoginRe.FindAllStringSubmatchIndex(f.code, -1) {
			if springDisabledRe.MatchString(f.code[m[1]:]) {
				continue
			}
			what := "form login"
			if f.code[m[2]:m[3]] == "httpBasic" {
				what = "HTTP Basic"
			}
			out = append(out, bruteForceHit{rule: BruteForceRuleID, file: f.path, line: lineAt(f.lineStarts, m[0]), route: "Spring Security " + what, kind: "a password check"})
		}
	}
	return out
}

func buildBruteForceFinding(h bruteForceHit) findings.Finding {
	if h.rule == UnthrottledIssueRuleID {
		return findings.Finding{
			RuleID:     UnthrottledIssueRuleID,
			Severity:   findings.SeverityLow,
			Confidence: findings.ConfidenceMedium,
			Location:   findings.Location{FilePath: h.file, StartLine: h.line, EndLine: h.line},
			Message: fmt.Sprintf("%s %s for an anonymous caller with no rate limit or throttle that this reader can see on the route, its router, the application or the handler: mass account creation or message flooding (CWE-770). A limit in a proxy or gateway is not visible here.",
				h.route, h.kind),
			Metadata: map[string]string{"cwe": "CWE-770", "route": h.route},
		}
	}
	return findings.Finding{
		RuleID:     BruteForceRuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: h.file, StartLine: h.line, EndLine: h.line},
		Message: fmt.Sprintf("%s performs %s with no rate limit, throttle or lockout that this reader can see on the route, its router, the application or the handler: unlimited guessing (CWE-307). A limit in a proxy or gateway is not visible here.",
			h.route, h.kind),
		Metadata: map[string]string{
			"cwe":   "CWE-307",
			"route": h.route,
		},
	}
}
