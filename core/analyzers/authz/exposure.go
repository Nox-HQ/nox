package authz

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// Two further claims are made over the same route inventory AUTHZ-001 reads.
//
// AUTHN-001, THE PROPOSITION.
//
//	A route that reads or changes something an anonymous caller should not
//	reach (an administrative or account-bearing path, or a DELETE, PUT or PATCH)
//	has no authentication anything in front of it, or inside it, shows:
//	no auth middleware on the route, its router, a matching prefix or the
//	mount; no auth decorator, dependency or before_request gate; and no read of
//	the caller's identity in the handler.
//
// It is a Lead by default and a finding on request (scan.rules.enable), for
// the reason AUTHZ-001 is: the source cannot rule out a public route, a gateway
// that authenticates before the app sees the request, or middleware this reader
// does not evaluate. `nox model` reads the same route table, so the lead and
// the model's "no authentication middleware visible" are one fact, not two.
//
// WEBHOOK-001, THE PROPOSITION.
//
//	A POST route receives a known provider's webhook (Stripe, GitHub or
//	Slack: the provider's path, header or event type is in the route or its
//	handler) and neither the handler, what it calls, nor the middleware in
//	front of it verifies the provider's signature: webhook payload accepted
//	without signature verification.
//
// It is a finding, not a lead, because the handler is read in full and a
// verification that exists has to be somewhere this reader looks: the handler,
// the functions it calls, or the route's middleware. A route whose handler
// cannot be read is not reported. What the reader cannot see: verification in
// a reverse proxy or gateway, and a provider SDK that mounts its own route
// (Bolt, Probot, @octokit/webhooks), which is recognised and skipped.

// Rule IDs for the two claims.
const (
	AuthnRuleID   = "AUTHN-001"
	WebhookRuleID = "WEBHOOK-001"
)

// Lead categories.
const (
	CategoryAuthorization  = "authorization"
	CategoryAuthentication = "authentication"
)

// routeView is one route as the exposure checks see it.
type routeView struct {
	route Route
	// handler is the comment-free text of the route's handler, its inline
	// middleware and the functions they call (one level, resolved within the
	// repository). Empty when the handler could not be read.
	handler string
	// known: the handler itself was read.
	known bool
	// chain is the text of the middleware on the route's chain.
	chain string
	// guardUnseen: the route sits where a global guard may apply that this
	// reader could not attribute to it, so an empty Authn proves nothing.
	guardUnseen bool
	framework   string
}

// ---- comment stripping ----

// withoutComments returns raw with every comment byte blanked and offsets kept,
// so a word in a comment can neither make a route look verified nor hide one.
func withoutComments(lang lexctx.Lang, raw []byte) string {
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

// ---- inline authentication ----

var (
	jsInlineAuthRe = regexp.MustCompile(`(?i)\b(?:req|request|ctx|context|c|event)\s*\??\.\s*(?:user|auth|session|currentUser|principal|identity|claims|account|isAuthenticated|oidc|jwt|userId|state\s*\.\s*user)\b` +
		`|\bheaders\s*\??\.\s*authorization\b|\bheaders\s*\[\s*['"](?:authorization|x-api-key|x-auth-token|x-access-token)['"]` +
		`|\.(?:get|header)\s*\(\s*['"](?:authorization|x-api-key|x-auth-token|x-access-token)['"]` +
		`|\.cookies\s*\??\.\s*\w*(?:token|session|jwt|auth)\w*|\bcookies\s*\.\s*get\s*\(\s*['"]\w*(?:token|session|jwt|auth)` +
		`|\bres\s*\.\s*locals\s*\.\s*(?:user|auth|session)|\bgetServerSession\s*\(|\bgetSession\s*\(|\bgetAuth\s*\(|\bcurrentUser\s*\(|\bjwt\s*\.\s*verify\s*\(|\bjwtVerify\s*\(` +
		`|\bpassport\s*\.\s*authenticate\s*\(|\bisAuthenticated\s*\(|\b(?:status|sendStatus|code)\s*\(\s*40[13]\b|\bUnauthori[sz]ed\b|\bForbidden\b|\bctx\s*\.\s*throw\s*\(\s*40[13]`)

	pyInlineAuthRe = regexp.MustCompile(`\bcurrent_user\b|\brequest\s*\.\s*(?:user|auth)\b|\bg\s*\.\s*(?:user|current_user|principal)\b|\bsession\s*(?:\[|\.\s*get\s*\()` +
		`|\bget_jwt(?:_identity)?\s*\(|\bverify_jwt_in_request\b|\bcurrent_identity\b|\brequest\s*\.\s*state\s*\.\s*(?:user|auth)\b|\brequest\s*\.\s*(?:headers|META)\s*(?:\.\s*get\s*\(|\[)\s*['"](?i:authorization|x-api-key|http_authorization)['"]` +
		`|\babort\s*\(\s*40[13]\b|status_code\s*=\s*(?:401|403|status\s*\.\s*HTTP_40[13]\w*)|\bHTTP_40[13]_\w+|\bUnauthori[sz]ed\b|\bPermissionDenied\b|\bis_authenticated\b|\bauthenticate\w*\s*\(|\bcheck_auth\w*\s*\(`)

	// pySecurityParamRe: a FastAPI/Starlette parameter that carries the caller.
	pySecurityParamRe = regexp.MustCompile(`(?i)\b(?:Security|OAuth2\w*|HTTPBearer|HTTPBasic|APIKey\w*|Authorization|credentials|current_user|token|principal)\b`)
)

const inlineAuthLabel = "an inline check on the caller's identity"

// ---- path classification ----

// publicSegments are path segments of routes that are public by design:
// credential exchange, health and metrics, documentation, third-party
// callbacks, and public forms. A route under one is never a missing-auth lead.
var publicSegments = setOf(
	"login", "logout", "signin", "signout", "sign-in", "sign-out", "signup", "sign-up", "register", "registration",
	"health", "healthz", "healthcheck", "health-check", "ready", "readyz", "live", "livez", "ping", "status", "version", "metrics", "heartbeat",
	"public", "static", "assets", "favicon.ico", "robots.txt", "sitemap.xml", "docs", "swagger", "openapi", "openapi.json", "redoc", "api-docs",
	"auth", "oauth", "oauth2", "token", "callback", "forgot", "forgot-password", "reset", "reset-password", "verify", "verify-email", "confirm", "activate",
	"csrf", "sso", "saml", "oidc", "contact", "subscribe", "newsletter", ".well-known", "unsubscribe", "captcha", "jwks", "jwks.json", "session", "sessions", "refresh",
)

// privilegedSegments are path segments of routes an anonymous caller should
// not reach on any method: administration and the keys to it.
var privilegedSegments = setOf(
	"admin", "administrator", "internal", "manage", "management", "console", "superuser", "backoffice",
	"secrets", "keys", "apikeys", "api-keys", "roles", "permissions", "tenants",
	"export", "exports", "backup", "backups", "debug", "dump",
)

// recordSegments are path segments of routes that serve one account's records.
// An anonymous GET of a list is often a public directory, so these count only
// for a GET that names a record (a path parameter), and for the mutating
// methods that count on any path.
var recordSegments = setOf(
	"users", "user", "accounts", "account", "customers", "customer", "members", "employees",
	"orders", "invoices", "billing", "payments", "payment", "subscriptions", "transactions", "wallet",
	"settings", "reports", "organizations", "orgs",
)

var pathParamStripRe = regexp.MustCompile(`^(?::.*|\{.*\}|<.*>|\*.*)$`)

func pathSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(strings.ToLower(p), "/") {
		if s == "" || pathParamStripRe.MatchString(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// feedLike: a syndication feed, which is public by nature.
func feedLike(p string) bool {
	p = strings.ToLower(p)
	return strings.HasSuffix(p, ".rss") || strings.HasSuffix(p, ".atom") || strings.HasSuffix(p, ".xml")
}

func hasPathParam(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s != "" && pathParamStripRe.MatchString(s) && !strings.HasPrefix(s, "*") {
			return true
		}
	}
	return false
}

func hasSegment(segs []string, set map[string]bool) bool {
	for _, s := range segs {
		if set[s] || strings.HasPrefix(s, "webhook") {
			return true
		}
	}
	return false
}

func isWebhookSegment(segs []string) bool {
	for _, s := range segs {
		if strings.HasPrefix(s, "webhook") || s == "hooks" || s == "hook" {
			return true
		}
	}
	return false
}

// nonProductionDirs are directory names whose routes are not an application's
// own: tests, fixtures and examples register routes to exercise a framework
// (express's own test/ tree registers `app.get('/user/:id')` several hundred
// times), and flagging them says nothing about a deployed service.
var nonProductionDirs = setOf("test", "tests", "__tests__", "spec", "specs", "e2e", "cypress", "fixtures", "fixture", "testdata", "mocks", "__mocks__",
	"example", "examples", "sample", "samples", "demo", "demos", "playground", "docs", "doc", "benchmark", "benchmarks", "bench",
	// Browser code and shipped assets: `api.put('/users/1/ban')` in a client
	// bundle is a call to a server, not a route registration.
	"public", "static", "client", "assets", "dist", "build", "vendor", "node_modules", "codefixes")

func nonProductionPath(p string) bool {
	dir := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	segs := strings.Split(dir, "/")
	for _, s := range segs[:len(segs)-1] {
		if nonProductionDirs[s] {
			return true
		}
	}
	return false
}

// missingAuthLead reports whether v meets AUTHN-001's proposition, and the
// lead that records it.
func missingAuthLead(v routeView) (Lead, bool) {
	r := v.route
	if r.Authn != "" || r.Authz != "" || v.guardUnseen || nonProductionPath(r.FilePath) {
		return Lead{}, false
	}
	if r.Path == "" || r.Path == "/" || strings.Contains(r.Path, "*") && len(pathSegments(r.Path)) == 0 {
		return Lead{}, false
	}
	segs := pathSegments(r.Path)
	if len(segs) == 0 || hasSegment(segs, publicSegments) || isWebhookSegment(segs) {
		return Lead{}, false
	}
	if feedLike(r.Path) {
		return Lead{}, false
	}
	mutating := r.Method == "DELETE" || r.Method == "PUT" || r.Method == "PATCH"
	privileged := hasSegment(segs, privilegedSegments)
	record := r.Method == "GET" && hasSegment(segs, recordSegments) && hasPathParam(r.Path)
	if !privileged && !mutating && !record {
		return Lead{}, false
	}
	return Lead{
		Method: r.Method, Path: r.Path, FilePath: r.FilePath, Line: r.Line,
		Category: CategoryAuthentication, RuleID: AuthnRuleID,
		Statement: "has no visible authentication: no auth middleware, decorator, dependency or check on the caller's identity",
		Test:      "Call it with no credentials. A 2xx answer with data means anyone can reach it; if it is public by design, no action is needed.",
	}, true
}

// ---- webhooks ----

type webhookProvider struct {
	name string
	// evidence: the route or its handler is this provider's receiver.
	pathRe, handlerRe *regexp.Regexp
	// verifyRe: the handler (or what it calls) verifies this provider's signature.
	verifyRe *regexp.Regexp
	// libRe: a file that mounts a provider SDK which verifies on its own.
	libRe *regexp.Regexp
	// what is forged, for the message.
	example string
	header  string
}

// genericVerifyRe is verification evidence for any provider: a signature or
// HMAC check by name, or a constant-time comparison.
var genericVerifyRe = regexp.MustCompile(`(?i)\b\w*(?:verify|validate|check|authenticate|assert)\w*(?:signature|webhook|hmac|sig)\w*\s*\(` +
	`|\b\w*(?:signature|webhook|hmac)\w*(?:verify|valid|check)\w*\s*\(` +
	`|\bcreateHmac\b|\btimingSafeEqual\b|\bcompare_digest\b|\bhmac\s*\.\s*(?:new|compare_digest|Equal)\b|\bsubtle\s*\.\s*ConstantTimeCompare\b|\bhash_equals\b`)

var webhookProviders = []webhookProvider{
	{
		name:      "Stripe",
		pathRe:    regexp.MustCompile(`(?i)stripe`),
		handlerRe: regexp.MustCompile(`(?i)stripe-signature|stripe_signature|\bstripe\s*\.\s*webhooks\b|['"](?:checkout\.session\.(?:completed|expired|async_payment_\w+)|payment_intent\.(?:succeeded|payment_failed|created)|invoice\.(?:paid|payment_succeeded|payment_failed)|customer\.subscription\.(?:created|updated|deleted)|charge\.(?:succeeded|refunded|failed))['"]`),
		verifyRe:  regexp.MustCompile(`(?i)\bconstructEvent(?:Async)?\b|\bconstruct_event\b|\bverify_header\b|\bWebhookSignature\b|stripe-signature|stripe_signature|HTTP_STRIPE_SIGNATURE`),
		libRe:     regexp.MustCompile(`@golevelup/nestjs-stripe|stripe-event-types\b.*verify|fastify-stripe`),
		example:   "a forged checkout.session.completed or invoice.paid event",
		header:    "Stripe-Signature",
	},
	{
		name:      "GitHub",
		pathRe:    regexp.MustCompile(`(?i)github`),
		handlerRe: regexp.MustCompile(`(?i)x-github-event|x-github-delivery|http_x_github_event|x_github_event`),
		verifyRe:  regexp.MustCompile(`(?i)x-hub-signature|http_x_hub_signature|x_hub_signature|\bwebhooks\s*\.\s*verify\b|\bverify_signature\b`),
		libRe:     regexp.MustCompile(`@octokit/webhooks|probot|smee-client|github-webhook-handler`),
		example:   "a forged push or pull_request event",
		header:    "X-Hub-Signature-256",
	},
	{
		name:      "Slack",
		pathRe:    regexp.MustCompile(`(?i)slack`),
		handlerRe: regexp.MustCompile(`(?i)url_verification|x-slack-signature|x-slack-request-timestamp|http_x_slack_signature`),
		verifyRe:  regexp.MustCompile(`(?i)x-slack-signature|x-slack-request-timestamp|http_x_slack_signature|signing_?secret|SignatureVerifier|verifyRequestSignature|verify_request|verification_?token`),
		libRe:     regexp.MustCompile(`@slack/bolt|slack_bolt|@slack/events-api|slack-events-api|@slack/interactive-messages`),
		example:   "a forged event, command or interactive payload",
		header:    "X-Slack-Signature",
	},
}

// slackPathRe: a Slack route is a receiver only under an events/commands/
// interactivity/webhook segment, not any path that mentions Slack.
var slackPathRe = regexp.MustCompile(`(?i)events?|commands?|interact|actions?|webhook|hooks?`)

type webhookHit struct {
	provider string
	route    Route
	header   string
	example  string
}

// unverifiedWebhook reports whether v is a provider's webhook receiver with no
// signature verification anywhere this reader looks.
func unverifiedWebhook(v routeView) (webhookHit, bool) {
	r := v.route
	if !v.known || (r.Method != "POST" && r.Method != "ALL") || nonProductionPath(r.FilePath) {
		return webhookHit{}, false
	}
	for _, p := range webhookProviders {
		if !receivesWebhook(p, v) {
			continue
		}
		if p.libRe.MatchString(v.handler) || p.verifyRe.MatchString(v.handler) || genericVerifyRe.MatchString(v.handler) {
			return webhookHit{}, false
		}
		if verifierMiddleware(v.chain) {
			return webhookHit{}, false
		}
		return webhookHit{provider: p.name, route: r, header: p.header, example: p.example}, true
	}
	return webhookHit{}, false
}

func receivesWebhook(p webhookProvider, v routeView) bool {
	if p.handlerRe.MatchString(v.handler) {
		return true
	}
	segs := pathSegments(v.route.Path)
	if !p.pathRe.MatchString(v.route.Path) {
		return false
	}
	if p.name == "Slack" {
		return slackPathRe.MatchString(v.route.Path)
	}
	return isWebhookSegment(segs) || strings.Contains(strings.ToLower(v.route.Path), "webhook")
}

// verifierMiddlewareRe: middleware named for verifying a signature. A bare
// `verify` is not enough (body parsers take a `verify` option); the name has to
// say what is verified.
var verifierMiddlewareRe = regexp.MustCompile(`(?i)(?:verify|validate|check|authenticate|require|assert)\w*(?:signature|webhook|hmac|sig)|(?:signature|webhook|hmac)\w*(?:verif|valid|check|guard)|stripe\w*webhook\w*middleware|webhook\s*\.\s*(?:verify|middleware)`)

func verifierMiddleware(chain string) bool { return verifierMiddlewareRe.MatchString(chain) }

func buildWebhookFinding(h webhookHit) findings.Finding {
	msg := fmt.Sprintf(
		"Webhook payload accepted without signature verification: %s %s receives %s events and nothing in its handler, what it calls or its middleware verifies the %s header. Anyone who can reach the URL can post %s. Verify the signature over the raw request body with the endpoint's signing secret before acting on the payload.",
		h.route.Method, h.route.Path, h.provider, h.header, h.example)
	return findings.Finding{
		RuleID:     WebhookRuleID,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: h.route.FilePath, StartLine: h.route.Line, EndLine: h.route.Line},
		Message:    msg,
		Metadata: map[string]string{
			"cwe":      "CWE-345",
			"provider": h.provider,
			"route":    h.route.Method + " " + h.route.Path,
			"header":   h.header,
		},
	}
}

// exposures runs both claims over the route views, deterministically: leads
// sorted by file and line, webhook hits likewise, one per route.
func exposures(views []routeView) ([]Lead, []webhookHit) {
	var leads []Lead
	var hooks []webhookHit
	seenLead, seenHook := map[string]bool{}, map[string]bool{}
	for _, v := range views {
		key := fmt.Sprintf("%s:%d:%s %s", v.route.FilePath, v.route.Line, v.route.Method, v.route.Path)
		if l, ok := missingAuthLead(v); ok && !seenLead[key] {
			seenLead[key] = true
			leads = append(leads, l)
		}
		if h, ok := unverifiedWebhook(v); ok && !seenHook[key] {
			seenHook[key] = true
			hooks = append(hooks, h)
		}
	}
	sortLeads(leads)
	return leads, hooks
}

func buildAuthnFinding(l Lead) findings.Finding {
	return findings.Finding{
		RuleID:     AuthnRuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceLow,
		Location:   findings.Location{FilePath: l.FilePath, StartLine: l.Line, EndLine: l.Line},
		Message: fmt.Sprintf("%s %s has no visible authentication: no auth middleware, decorator, dependency or check on the caller's identity. Possible missing authentication (OWASP API2:2023). Verify by calling it with no credentials.",
			l.Method, l.Path),
		Metadata: map[string]string{
			"cwe":       "CWE-306",
			"owasp_api": "API2:2023",
			"route":     l.Method + " " + l.Path,
		},
	}
}

// pyGlobalGuardRe: application-wide request interception this reader does not
// evaluate, so an empty Authn on a route proves nothing about it.
var pyGlobalGuardRe = regexp.MustCompile(`\.add_middleware\s*\(|\bAuthenticationMiddleware\b|\.middleware\s*\(\s*['"]http['"]|\bwsgi_app\s*=|\bbefore_request_funcs\b`)
