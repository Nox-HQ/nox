// Package authz is nox's static detector for possible broken object-level
// authorization (BOLA / IDOR — OWASP API1:2023, CWE-639) in Express, Fastify,
// Flask and FastAPI servers.
//
// THE PROPOSITION. AUTHZ-001 claims exactly this, and nothing stronger:
//
//	A route that requires an authenticated caller looks up a record by a
//	caller-controlled identifier (an id-named route parameter, query
//	parameter or body field), and nothing this reader can see on that path
//	relates the record to the caller's principal.
//
// Each conjunct is something the source shows:
//
//   - "requires an authenticated caller": authentication middleware on the
//     route, on its router (`router.use(auth)`), on a matching path prefix
//     (`app.use('/api', auth)`), on the mount of the router file
//     (`app.use('/x', auth, xRouter)`), or an inline 401 on the principal.
//     That middleware is the intent signal. Without it the endpoint may be
//     public on purpose, which no reader of source can rule out, and that is
//     exactly the judgement the retired API-ABUSE-001 plugin rule tried to make
//     and scored precision 0.000 on.
//   - "loads a record by a caller-controlled identifier": the identifier flows,
//     through simple assignments and destructuring, into the key of a
//     data-access call (an ORM finder, a query builder, a SQL statement, or a
//     DAO/repository/service getter) inside the resolved handler.
//   - "nothing relates the record to the principal": none of the
//     counterexamples below is present.
//
// COUNTEREXAMPLES. Every legitimate way to enforce ownership that a reader of
// the handler can see refutes the proposition and the route is not reported:
// the lookup itself carries the principal (`WHERE id = $1 AND owner_id = $2`,
// `{ where: { id, userId: req.user.id } }`) or filters on an owner field whose
// value is not the caller's identifier; a data client hung off the request
// (`req.db`, `res.locals.tenantDb`: a tenant- or user-scoped connection);
// request context set by middleware handed to the data layer
// (`new ItemsService({ accountability: req.accountability })`, or the bare
// request to `repositoryFor(req)`) — any request member that is not caller
// input counts, because this reader cannot tell which custom property is the
// scope; a comparison of the record with the principal
// (`if (doc.owner !== req.user.id)`), unless it sits in a callback whose result
// is discarded and which can neither respond nor throw (instrumentation); a
// call that receives both (`assertCanRead(req.user, doc)`); a policy/ability
// call (CASL, casbin, `authorize(`); a 403 response; a read of the caller's
// role; authorization or record-loading middleware on the route chain
// (`requireRole('admin')`, `auth('manageUsers')`, `loadInvoiceForUser`); a
// `router.param()` loader for the parameter; and, repository-wide, Postgres
// row-level security. Each cleared candidate is filed in the reasoning ledger
// with its reason (RecordReasoningTo), never dropped silently.
//
// LEADS BY DEFAULT, FINDINGS ON REQUEST. Measured on 22 pinned open-source
// Express apps (see the PR and CHANGELOG for the counts): every finding on the
// ordinary apps was a real authorization defect, but a quarter of the findings
// on deliberately vulnerable apps were resources shared by design (a
// picture's likes, a public profile, a shared product catalogue), a class no
// reader of source can refute, and the ordinary apps that produced findings
// at all were three. That is not enough to put a medium finding in front of
// every scan. So by default each such route is a Lead, presented as a
// two-account test to run, and scan.rules.enable: [AUTHZ-001] makes each a
// finding instead.
//
// WHAT IT CANNOT SEE, and therefore why it says "possible": a check inside a
// service the handler calls without passing the principal through a visible
// argument; ownership enforced by an ORM default scope, an AsyncLocalStorage
// context or a database view; and resources that are shared by design (any
// authenticated user may read any product). The first three are false
// positives a runtime test settles; the last is a product decision. So the
// finding is Exploitability POTENTIAL (every static finding is) and its
// remediation names the runtime test that confirms or refutes it: request the
// record as a second, unrelated principal.
//
// SCOPE. What is read, and nothing else:
//
//   - Express (and koa-router, which shares the registration shape) and Fastify
//     in JavaScript and TypeScript: `app.get(path, [opts], handler)`,
//     `fastify.route({ method, url, preHandler, handler })`, plugins mounted
//     with `register(plugin, { prefix })`, hooks (`addHook('onRequest', auth)`,
//     `preHandler: [auth]`) and `request.params.id`.
//   - Flask in Python: `@app.route` / `@app.get`, Blueprints with `url_prefix`
//     (also nested, and overridden at `register_blueprint`), `<int:id>`
//     converters, login/JWT decorators and `before_request` gates.
//   - FastAPI in Python: `@app.get`, `APIRouter(prefix=…)` composed with
//     `include_router(prefix=…)` (a prefix held in a settings constant is
//     resolved when the constant is unique), path parameters as function
//     arguments, `Depends(get_current_user)` — directly, through an
//     `Annotated[…]` alias or as router-level `dependencies` — read as
//     AUTHENTICATION, never as ownership.
//
// A Python route is judged the same way as a JavaScript one: the same
// proposition, the same counterexample classes, the same Lead. The reader is
// text over a lexically masked copy of the file, not a Python parser.
//
// NOT read: NestJS and other decorator frameworks, Next.js route handlers,
// Django (urls.py + views), Flask class-based views and Flask-RESTful
// resources, Starlette/Sanic/Quart/aiohttp/Tornado routes, custom
// route-definition helpers, handlers that read parameters through a validation
// helper (`parseReq(req, schema)`) or a FastAPI dependency that itself loads
// the record (`item = Depends(valid_item_id)`), lookups keyed by a non-id
// field (username, email, slug), auto-generated REST layers with no handler in
// source, and Python code that builds a query across several statements
// without re-binding the same name.
//
// Authorization claims a reader cannot see in a FastAPI app: a global
// `AuthenticationMiddleware`, `app.add_middleware`, and routes whose router is
// created in another repository.
package authz

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
	nsource "github.com/nox-hq/nox/core/source"
)

// RuleID is the rule this analyzer emits.
const RuleID = "AUTHZ-001"

// Analyzer is the object-level authorization analyzer.
//
// It runs on every scan that includes application code. What it produces
// depends on whether AUTHZ-001 is enabled: enabled, each route that meets the
// proposition is a finding; not enabled (the default), each is a Lead, which
// the scan carries beside the findings and the assessment presents as
// something to test. A lead is never a finding: it does not reach
// findings.json, SARIF, the exit code or a fingerprint.
type Analyzer struct {
	enabled   bool
	reasoning *reasoning.Store
	leads     []Lead
	routes    int
	routeList []Route
	// authnEnabled: AUTHN-001 reports findings instead of leads.
	authnEnabled bool
}

// Route is one Express route registration this reader found, with the access
// control it can attribute to the route by name.
//
// It is the evidence under a system description (what entry points exist and
// what stands in front of them), not a verdict: Authn and Authz are the
// middleware expressions the reader attributed to the route, read as text, and
// an empty Authn means only that no authentication middleware is visible to
// this reader. A handler that checks the caller inline, a framework that
// authenticates before Express sees the request, or a route that is public on
// purpose all look the same here.
type Route struct {
	// Method is upper-case (GET, POST, ALL); Path includes the prefix its
	// router is mounted at when this reader resolved the mount.
	Method string
	Path   string
	// FilePath and Line locate the registration.
	FilePath string
	Line     int
	// Authn and Authz are the first authentication and the first
	// authorization (or record-loading) middleware on the route's chain.
	Authn string
	Authz string
}

// Lead is a route that meets AUTHZ-001's proposition, reported as something to
// verify rather than as a finding.
type Lead struct {
	// Method and Path name the route, Path including the prefix its router
	// is mounted at when this reader resolved the mount.
	Method string
	Path   string
	// FilePath and Line locate the record lookup.
	FilePath string
	Line     int
	// IDSource is where the identifier comes from: path, query or body.
	IDSource string
	// Category, RuleID, Statement and Test are set by claims other than
	// AUTHZ-001's (AUTHN-001); empty means an object-level authorization lead.
	Category  string
	RuleID    string
	Statement string
	Test      string
}

// Enabled reports whether AUTHZ-001 reports findings on this scan.
func (a *Analyzer) Enabled() bool { return a.enabled }

// AuthnEnabled reports whether AUTHN-001 reports findings on this scan.
func (a *Analyzer) AuthnEnabled() bool { return a.authnEnabled }

// Leads returns the routes the last ScanArtifacts call held as leads, sorted
// by file and line. Empty when AUTHZ-001 is enabled: those routes are
// findings, and a route is never both.
func (a *Analyzer) Leads() []Lead { return a.leads }

// Coverage names, for the scan's "Checks completed", exactly the frameworks
// this analyzer reads. Keep it equal to the package documentation's SCOPE.
const Coverage = "Express, Fastify, Flask, FastAPI routes"

// RoutesRead is how many route registrations (Express, Fastify, Flask,
// FastAPI) the last ScanArtifacts call read. Zero means the scan saw none and
// has nothing to say about authorization.
func (a *Analyzer) RoutesRead() int { return a.routes }

// Routes returns every route registration the last ScanArtifacts call read,
// sorted by file, line, method and path. It is the same set RoutesRead counts.
func (a *Analyzer) Routes() []Route { return a.routeList }

// RecordReasoningTo directs this analyzer's refutations at store: every route
// that met the proposition's antecedent (authenticated, identifier-keyed
// lookup) and was then cleared by a counterexample is filed with the reason,
// so stage accounting can count AUTHZ candidates against what was refuted.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// NewAnalyzer returns the analyzer. AUTHZ-001 is opt-in: it reports findings
// only when EnableOptIn names it (scan.rules.enable), and leads otherwise.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// EnableOptIn turns AUTHZ-001 on when ids names it.
func (a *Analyzer) EnableOptIn(ids []string) {
	for _, id := range ids {
		switch id {
		case RuleID:
			a.enabled = true
		case AuthnRuleID:
			a.authnEnabled = true
		}
	}
}

// Rules declares AUTHZ-001.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          RuleID,
		Version:     "1.0",
		Description: "Possible broken object-level authorization: an authenticated route loads a record by a caller-supplied id with no visible check that the record belongs to the caller (OWASP API1:2023, IDOR)",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceLow,
		OptIn:       true,
		Tags:        []string{"authorization", "bola", "idor", "owasp-a01", "express", "fastify", "flask", "fastapi"},
		Remediation: "Scope the lookup to the caller (`WHERE id = $1 AND owner_id = $2` with the principal's id, `{ where: { id, ownerId: req.user.id } }`, `Order.query.filter_by(id=order_id, user_id=current_user.id)`, or `select(Item).where(Item.id == id, Item.owner_id == user.id)`), or load the record and reject the request when it does not belong to the caller (`if (doc.ownerId !== req.user.id) return res.sendStatus(404)`, `if item.owner_id != current_user.id: raise HTTPException(status_code=404)`), or route it through your policy layer. A Depends(get_current_user) dependency authenticates the caller; it does not scope the record. If the resource is shared by design, waive the finding with that reason. To confirm before changing code: create a record as user A, request it with user B's credentials; a 200 with A's data confirms the finding.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			"https://cwe.mitre.org/data/definitions/639.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-639", "owasp_api": "API1:2023"},
	})
	rs.Add(&rules.Rule{
		ID:          AuthnRuleID,
		Version:     "1.0",
		Description: "Possible missing authentication: an administrative or account-bearing route, or a DELETE, PUT or PATCH route, has no authentication middleware, decorator, dependency or check on the caller's identity that this reader can see (OWASP API2:2023, CWE-306)",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceLow,
		OptIn:       true,
		Tags:        []string{"authentication", "missing-auth", "owasp-a07", "express", "fastify", "flask", "fastapi"},
		Remediation: "Put authentication in front of the route: middleware on the route or its router (`router.use(requireAuth)`), a decorator (`@login_required`, `@jwt_required()`), or a dependency (`Depends(get_current_user)`). If a gateway or an application-wide middleware nox does not evaluate already authenticates it, or the route is public by design, waive the finding with that reason. To confirm before changing code: call the route with no credentials; a 2xx answer with data confirms it.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		Metadata: map[string]string{"cwe": "CWE-306", "owasp_api": "API2:2023"},
	})
	rs.Add(&rules.Rule{
		ID:          WebhookRuleID,
		Version:     "1.0",
		Description: "Webhook payload accepted without signature verification: a POST route receives a Stripe, GitHub or Slack webhook and neither its handler, what it calls, nor its middleware verifies the provider's signature (CWE-345)",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"webhook", "signature", "stripe", "github", "slack", "express", "fastify", "flask", "fastapi"},
		Remediation: "Verify the signature over the RAW request body with the endpoint's signing secret before acting on the payload: Stripe `stripe.webhooks.constructEvent(rawBody, req.headers['stripe-signature'], secret)` (Python `stripe.Webhook.construct_event`), GitHub an HMAC-SHA256 of the body compared in constant time with `X-Hub-Signature-256`, Slack the v0 signature over `v0:{timestamp}:{body}` from `X-Slack-Signature` with the signing secret. Reject the request when it does not match. If verification happens in a gateway nox cannot see, waive the finding with that reason.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/345.html",
			"https://docs.stripe.com/webhooks#verify-events",
			"https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
			"https://api.slack.com/authentication/verifying-requests-from-slack",
		},
		Metadata: map[string]string{"cwe": "CWE-345"},
	})
	return rs
}

// index is the repository's JavaScript/TypeScript as one unit: routes and
// handlers live in different files, and so does the middleware that guards
// them.
type index struct {
	routes    int
	routeList []Route
	leads     []Lead
	files     map[string]*jsFile
	order     []string
	rls       bool
	reasoning *reasoning.Store
	views     []routeView
}

var jsExt = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true}

var rlsRe = regexp.MustCompile(`(?i)\benable\s+row\s+level\s+security\b|\bcreate\s+policy\s`)

// ScanArtifacts reports AUTHZ-001 findings. It is deterministic: files are
// read in path order and findings are sorted.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	a.leads, a.routes, a.routeList = nil, 0, nil
	ix := &index{files: map[string]*jsFile{}}
	if a.enabled {
		// Refutations are filed only when the rule reports: in lead mode no
		// AUTHZ candidate is a finding, so none belongs in stage accounting.
		ix.reasoning = a.reasoning
	}
	rls := false
	pyFiles, pyOrder := map[string]*pyFile{}, []string(nil)
	ordered := make([]discovery.Artifact, len(artifacts))
	copy(ordered, artifacts)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for i := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := ordered[i]
		ext := strings.ToLower(filepath.Ext(art.Path))
		if ext == ".sql" && !rls {
			if b, err := os.ReadFile(art.AbsPath); err == nil && rlsRe.Match(b) {
				rls = true
			}
			continue
		}
		if art.Type != discovery.Source || (!jsExt[ext] && ext != ".py") || nsource.IsTestPath(art.Path) {
			continue
		}
		raw, err := os.ReadFile(art.AbsPath)
		if err != nil || nsource.IsGenerated(raw) {
			continue
		}
		if !rls && rlsRe.Match(raw) {
			rls = true
		}
		p := filepath.ToSlash(art.Path)
		if ext == ".py" {
			pyFiles[p] = &pyFile{path: p, raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangPython, raw)), sans: withoutComments(lexctx.LangPython, raw), lineStarts: computeLineStarts(raw)}
			pyOrder = append(pyOrder, p)
			continue
		}
		ix.files[p] = &jsFile{path: p, raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangJavaScript, raw)), sans: withoutComments(lexctx.LangJavaScript, raw), lineStarts: computeLineStarts(raw)}
		ix.order = append(ix.order, p)
	}
	// Row-level security moves the ownership check into the database, where
	// no handler shows it: every candidate is refuted, and recorded as such.
	ix.rls = rls
	reported := ix.findings()
	a.routes = ix.routes
	a.routeList = ix.routeList
	leads := ix.leads
	views := ix.views
	if len(pyOrder) > 0 {
		py := newPyIndex(pyFiles, pyOrder, rls)
		res := py.findings()
		a.routes += len(py.routes)
		inv, pyViews := py.routeInventory()
		a.routeList = append(a.routeList, inv...)
		views = append(views, pyViews...)
		sortRoutes(a.routeList)
		reported = append(reported, res.findings...)
		leads = append(leads, res.leads...)
		sortLeads(leads)
		if a.enabled {
			for _, rf := range res.refuted {
				refuteTo(ix.reasoning, rf.path, rf.line, rf.reason, "the Flask and FastAPI route reader, over this repository's Python")
			}
		}
	}
	exposed, hooks := exposures(views)
	for _, h := range hooks {
		fs.Add(buildWebhookFinding(h))
	}
	if !a.authnEnabled {
		leads = append(leads, exposed...)
		sortLeads(leads)
	} else {
		for _, l := range exposed {
			fs.Add(buildAuthnFinding(l))
		}
	}
	if !a.enabled {
		a.leads = leads
		return fs, nil
	}
	for _, f := range reported {
		fs.Add(f)
	}
	a.leads = nil
	if !a.authnEnabled {
		a.leads = exposed
	}
	return fs, nil
}

// mwRef is one middleware expression in the file it was written in.
type mwRef struct {
	file *jsFile
	s    span
}

func (m mwRef) text() string { return m.file.code[m.s.start:m.s.end] }

func (ix *index) findings() []findings.Finding {
	spec := resolveSpecifier(ix.files)
	for _, p := range ix.order {
		parseImports(ix.files[p], spec)
	}
	mount := mountTarget(spec)
	uses := map[string][]use{}
	var routes []route
	params := map[string]map[string]bool{}
	for _, p := range ix.order {
		f := ix.files[p]
		uses[p] = append(parseUses(f, mount), parseFastifyUses(f, mount)...)
		routes = append(routes, parseRoutes(f)...)
		params[p] = parseParamLoaders(f)
	}
	inherited := ix.inheritedMiddleware(uses)
	prefixes := ix.mountPrefixes(uses)
	ix.routes = len(routes)
	ix.routeList, ix.views = ix.routeInventory(routes, uses, inherited, prefixes)

	// One handler can serve several routes. A subject is reported if ANY of
	// its routes meets the proposition, and refuted only if every route that
	// reached it was cleared.
	type refutation struct {
		path   string
		line   int
		reason string
	}
	reported := map[string]bool{}
	refuted := map[string]refutation{}
	var subjects []string
	var out []findings.Finding
	for i := range routes {
		r := &routes[i]
		idParams := map[string]bool{}
		loaded := ""
		for _, p := range r.params {
			if !idishRe.MatchString(p) {
				continue
			}
			idParams[p] = true
			if params[r.file.path][p] && loaded == "" {
				loaded = p
			}
		}
		bodyPrincipal := writesPrincipal(routeChain(r, r.args, uses[r.file.path], inherited[r.file.path]))
		hIdx, h, facts := ix.handlerOf(r, idParams, bodyPrincipal)
		if hIdx < 0 {
			continue // no identifier-keyed lookup this reader can see
		}
		var mw []span
		for j, a := range r.args {
			if j != hIdx {
				mw = append(mw, a)
			}
		}
		authn, authz := classifyChain(routeChain(r, mw, uses[r.file.path], inherited[r.file.path]))
		if authn == "" && authz == "" && !facts.inlineAuth {
			// The antecedent fails: nothing says the route is meant to be
			// private. That is not a refutation; the route is no candidate.
			continue
		}
		sink := facts.sinks[0]
		line := lineAt(h.file.lineStarts, sink.off)
		subject := fmt.Sprintf("%s:%d", h.file.path, line)
		if reported[subject] {
			continue
		}
		if reason := ix.counterexample(facts, loaded, authz); reason != "" {
			if _, ok := refuted[subject]; !ok {
				refuted[subject] = refutation{h.file.path, line, reason}
				subjects = append(subjects, subject)
			}
			continue
		}
		if authn == "" {
			authn = "an inline 401 on the caller's principal"
		}
		reported[subject] = true
		out = append(out, newFinding(r, h, sink, authn))
		ix.leads = append(ix.leads, Lead{
			Method:   strings.ToUpper(r.method),
			Path:     joinRoutePath(prefixes[r.file.path], r.path),
			FilePath: h.file.path,
			Line:     line,
			IDSource: idSources(sink.idFrom),
		})
	}
	sort.SliceStable(ix.leads, func(i, j int) bool {
		a, b := ix.leads[i], ix.leads[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Method+" "+a.Path < b.Method+" "+b.Path
	})
	for _, subject := range subjects {
		if rf := refuted[subject]; !reported[subject] {
			ix.refute(rf.path, rf.line, rf.reason)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location.FilePath != out[j].Location.FilePath {
			return out[i].Location.FilePath < out[j].Location.FilePath
		}
		return out[i].Location.StartLine < out[j].Location.StartLine
	})
	return out
}

// routeInventory describes every route, whether or not it meets AUTHZ-001's
// proposition. The handler is taken to be the last argument and everything
// before it middleware; that is a positional reading, not the body analysis the
// proposition uses, so it names what is visibly in front of the route and
// nothing more.
//
// It also reads each handler, because "no authentication middleware" is not
// "no authentication": a handler that rejects an anonymous caller itself is
// recorded as authenticated, so the inventory, `nox model` and AUTHN-001 agree.
func (ix *index) routeInventory(routes []route, uses map[string][]use, inherited map[string][]mwRef, prefixes map[string]string) ([]Route, []routeView) {
	out := make([]Route, 0, len(routes))
	views := make([]routeView, 0, len(routes))
	globalAuth := ix.hasGlobalAuth(uses)
	for i := range routes {
		r := &routes[i]
		var mw []span
		if len(r.args) > 1 {
			mw = r.args[:len(r.args)-1]
		}
		chain := routeChain(r, mw, uses[r.file.path], inherited[r.file.path])
		authn, authz := classifyChain(chain)
		if len(r.args) == 1 && authn == "" && authz == "" {
			// `app.get('/api/Users', security.isAuthorized())` registers a guard
			// for a route served elsewhere, not an endpoint.
			authn, authz = guardRegistration(chain, r)
		}
		handler, known := ix.handlerText(r)
		if authn == "" && authz == "" && jsInlineAuthRe.MatchString(handler) {
			authn = inlineAuthLabel
		}
		rt := Route{
			Method:   strings.ToUpper(r.method),
			Path:     joinRoutePath(prefixes[r.file.path], r.path),
			FilePath: r.file.path,
			Line:     lineAt(r.file.lineStarts, r.offset),
			Authn:    authn,
			Authz:    authz,
		}
		_, mounted := inherited[r.file.path]
		out = append(out, rt)
		views = append(views, routeView{
			route: rt, handler: handler, known: known, chain: chainText(chain),
			guardUnseen: globalAuth && !mounted && !appDeclRe.MatchString(r.file.code),
		})
	}
	sortRoutes(out)
	return out, views
}

var denyRe = regexp.MustCompile(`(?i)\b(?:deny|forbid|reject|block)\w*\s*\(`)

// guardRegistration reads a route registered with a single argument that is
// itself access control: authentication (`isAuthorized()`), authorization, or a
// blanket denial (`denyAll()`).
func guardRegistration(chain []mwRef, r *route) (authn, authz string) {
	only := mwRef{r.file, r.args[0]}
	authn, authz = classifyChain(append(append([]mwRef(nil), chain...), only))
	if authn == "" && authz == "" && denyRe.MatchString(only.text()) {
		authz = compact(only.text())
	}
	return authn, authz
}

var appDeclRe = regexp.MustCompile(`\b(?:express|[Ff]astify)\s*\(`)

// hasGlobalAuth reports whether some file applies authentication to every
// request (`app.use(requireAuth)`).
func (ix *index) hasGlobalAuth(uses map[string][]use) bool {
	for _, p := range ix.order {
		for _, u := range uses[p] {
			if len(u.mounts) > 0 || (u.prefix != "" && u.prefix != "/") {
				continue
			}
			var mw []mwRef
			for _, sp := range u.mw {
				mw = append(mw, mwRef{u.file, sp})
			}
			if authn, _ := classifyChain(mw); authn != "" {
				return true
			}
		}
	}
	return false
}

func chainText(chain []mwRef) string {
	var b strings.Builder
	for _, m := range chain {
		b.WriteString(m.text())
		b.WriteByte(' ')
	}
	return b.String()
}

var callNameRe = regexp.MustCompile(`([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(`)

// maxCallees bounds how many functions a handler is expanded into.
const maxCallees = 16

// handlerText returns the comment-free text of the route's handler and inline
// middleware plus the functions they call, and whether the handler itself (the
// last argument) was read.
func (ix *index) handlerText(r *route) (string, bool) {
	var parts []string
	known := false
	for j, a := range r.args {
		ref, ok := ix.resolveHandler(r.file, a, 0)
		if !ok {
			continue
		}
		if j == len(r.args)-1 {
			known = true
		}
		parts = append(parts, ref.file.sans[ref.s.start:ref.s.end])
		for _, c := range ix.callees(ref) {
			parts = append(parts, c.file.sans[c.s.start:c.s.end])
		}
	}
	return strings.Join(parts, "\n"), known
}

// callees resolves the functions called inside ref, one level deep.
func (ix *index) callees(ref fnRef) []fnRef {
	var out []fnRef
	seen := map[string]bool{}
	body := ref.file.code[ref.s.start:ref.s.end]
	for _, m := range callNameRe.FindAllStringSubmatch(body, -1) {
		name := strings.Join(strings.Fields(m[1]), "")
		if seen[name] || len(out) >= maxCallees {
			continue
		}
		seen[name] = true
		if c, ok := ix.resolveName(ref.file, name); ok && (c.file != ref.file || c.s != ref.s) {
			out = append(out, c)
		}
	}
	return out
}

// sortRoutes orders an inventory by file, line, method and path, so the JS and
// Python halves merge into one deterministic list.
func sortRoutes(rs []Route) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Method+" "+a.Path < b.Method+" "+b.Path
	})
}

// counterexample returns why a candidate route is not reported, or "".
func (ix *index) counterexample(facts bodyFacts, loaded, authz string) string {
	switch {
	case facts.refuted != "":
		return facts.refuted
	case loaded != "":
		return "router.param() loads :" + loaded + " for every route on the router"
	case authz != "":
		return "authorization middleware on the route (" + authz + ")"
	case ix.rls:
		return "the repository enables Postgres row-level security"
	}
	return ""
}

// refute files a cleared candidate in the reasoning ledger, scoped to what
// this reader can and cannot see.
func (ix *index) refute(path string, line int, reason string) {
	refuteTo(ix.reasoning, path, line, reason, "the Express and Fastify route reader, over this repository's JavaScript and TypeScript")
}

// routeChain is every middleware that runs before the route's handler that
// this reader can attribute: route-level, router-level and prefix `use` calls
// earlier in the same file, and middleware inherited from where the file's
// router is mounted.
func routeChain(r *route, routeMW []span, fileUses []use, inherited []mwRef) []mwRef {
	var chain []mwRef
	chain = append(chain, inherited...)
	for _, u := range fileUses {
		if u.receiver != r.receiver || u.offset > r.offset || len(u.mounts) > 0 {
			continue
		}
		if u.prefix != "" && !strings.HasPrefix(r.path, u.prefix) {
			continue
		}
		for _, s := range u.mw {
			chain = append(chain, mwRef{u.file, s})
		}
	}
	for _, s := range routeMW {
		chain = append(chain, mwRef{r.file, s})
	}
	return chain
}

// handlerOf picks the route argument that handles the request: the last one
// that resolves to a function loading a record by one of the route's
// identifiers. It returns -1 when no argument does.
func (ix *index) handlerOf(r *route, idParams map[string]bool, bodyPrincipal bool) (int, fnRef, bodyFacts) {
	for j := len(r.args) - 1; j >= 0; j-- {
		ref, ok := ix.resolveHandler(r.file, r.args[j], 0)
		if !ok {
			continue
		}
		if facts := analyzeBody(ref.file, ref.s, idParams, bodyPrincipal); len(facts.sinks) > 0 {
			return j, ref, facts
		}
	}
	return -1, fnRef{}, bodyFacts{}
}

// inheritedMiddleware computes, per file, the middleware applied where that
// file's router is mounted — transitively, so a router mounted by an index
// router mounted with auth inherits the auth.
func (ix *index) inheritedMiddleware(uses map[string][]use) map[string][]mwRef {
	direct := map[string][]mwRef{}
	parents := map[string][]string{}
	for _, p := range ix.order {
		for _, u := range uses[p] {
			if len(u.mounts) == 0 {
				continue
			}
			var mw []mwRef
			for _, prior := range uses[p] {
				if prior.receiver != u.receiver || prior.offset >= u.offset || len(prior.mounts) > 0 {
					continue
				}
				if prior.prefix != "" && !strings.HasPrefix(u.prefix, prior.prefix) {
					continue
				}
				for _, s := range prior.mw {
					mw = append(mw, mwRef{prior.file, s})
				}
			}
			for _, s := range u.mw {
				mw = append(mw, mwRef{u.file, s})
			}
			for _, t := range u.mounts {
				direct[t] = append(direct[t], mw...)
				parents[t] = append(parents[t], p)
			}
		}
	}
	out := map[string][]mwRef{}
	var visit func(p string, depth int, seen map[string]bool) []mwRef
	visit = func(p string, depth int, seen map[string]bool) []mwRef {
		if depth > 8 || seen[p] {
			return nil
		}
		seen[p] = true
		mw := append([]mwRef(nil), direct[p]...)
		for _, parent := range parents[p] {
			mw = append(mw, visit(parent, depth+1, seen)...)
		}
		return mw
	}
	for _, p := range ix.order {
		if len(parents[p]) > 0 {
			out[p] = visit(p, 0, map[string]bool{})
		}
	}
	return out
}

// mountPrefixes returns, per router file, the path prefix it is served under:
// the first mount of it that this reader resolved, composed with the prefix
// the mounting file is itself served under. A file mounted nowhere, or only
// without a prefix, maps to "".
func (ix *index) mountPrefixes(uses map[string][]use) map[string]string {
	type mount struct{ parent, prefix string }
	first := map[string]mount{}
	for _, p := range ix.order {
		for _, u := range uses[p] {
			for _, t := range u.mounts {
				if _, ok := first[t]; !ok {
					first[t] = mount{p, u.prefix}
				}
			}
		}
	}
	out := map[string]string{}
	for _, p := range ix.order {
		prefix, cur, seen := "", p, map[string]bool{}
		for depth := 0; depth < 8 && !seen[cur]; depth++ {
			seen[cur] = true
			m, ok := first[cur]
			if !ok {
				break
			}
			prefix = joinRoutePath(m.prefix, prefix)
			cur = m.parent
		}
		if prefix != "" {
			out[p] = prefix
		}
	}
	return out
}

// joinRoutePath joins a mount prefix and a route path: ("/api/invoices",
// "/:id") is "/api/invoices/:id" and ("/api/invoices", "/") is
// "/api/invoices".
func joinRoutePath(prefix, p string) string {
	prefix = strings.TrimRight(prefix, "/")
	switch {
	case prefix == "":
		return p
	case p == "" || p == "/":
		return prefix
	}
	return prefix + "/" + strings.TrimLeft(p, "/")
}

var (
	// notAccessControlRe names middleware that matches the vocabulary below
	// by accident: security headers, parsers, sessions and passport's
	// request-populating hooks enforce nothing about who the caller is.
	notAccessControlRe = regexp.MustCompile(`(?i)helmet|cors|featurepolicy|contentsecuritypolicy|referrerpolicy|permissionspolicy|frameguard|csrf|xss|hsts|nosniff|compression|morgan|bodyparser|urlencoded|express\s*\.\s*(?:json|static|raw|text)|serve|multer|upload|ratelimit|limiter|slowdown|cookieparser|^\s*session$|passport\s*\.\s*(?:initialize|session)|i18n|locale`)

	authzMWRe  = regexp.MustCompile(`[Rr]ole|[Aa]dmin|[Pp]ermi|\bcan[A-Z_]|\bcan$|[Aa]bilit|[Pp]olic|[Oo]wner|isOwn|[Ss]cope|\b[Aa]cl\b|ACL|[Rr]bac|RBAC|[Ss]taff|[Ss]uperuser|[Aa]ccounting|[Dd]eny|\bload[A-Z]|\bfetch[A-Z]|[Tt]enant|[Mm]ember|[Bb]elongs|[Rr]estrict|[Gg]rant|(?:check|has|can|require|verify)Access|[Aa]uthori[sz]e\b|[Aa]uthori[sz]ation`)
	authnArgRe = regexp.MustCompile(`^(?:[A-Za-z_$][\w$]*\s*\.\s*)?authenticate\s*\(`)
)

// classifyChain returns the first authentication middleware and the first
// authorization (or record-loading) middleware on the chain, by their text.
func classifyChain(chain []mwRef) (authn, authz string) {
	for _, m := range chain {
		t := strings.TrimSpace(m.text())
		raw := string(m.file.raw[m.s.start:m.s.end])
		name := t
		if inlineFnRe.MatchString(t) {
			// An inline middleware is judged by what it does.
			if authz == "" && (authzMWRe.MatchString(t) || forbiddenRe.MatchString(t)) {
				authz = compact(t)
			}
			if authn == "" && (unauthorizedRe.MatchString(t) || jwtVerifyRe.MatchString(t)) {
				authn = compact(t)
			}
			continue
		}
		if i := strings.IndexByte(t, '('); i >= 0 {
			name = t[:i]
		}
		if notAccessControlRe.MatchString(name) {
			continue
		}
		if authz == "" && (authzMWRe.MatchString(name) || permissionArg(t, raw)) {
			authz = compact(t)
		}
		if authn == "" && authnName(name) {
			authn = compact(t)
		}
	}
	return authn, authz
}

var camelRe = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+`)

// authnName reports whether a middleware name says it authenticates the
// caller. It reads the name as words (`requireAuth` = require+auth,
// `jwtChallenges` = jwt+challenges) so a word that only mentions a token or a
// JWT while doing something else — detecting a challenge, parsing a cookie,
// making auth optional — does not count.
func authnName(name string) bool {
	words := camelRe.FindAllString(name, -1)
	hit, sessionGate := false, false
	for _, w := range words {
		w = strings.ToLower(w)
		switch {
		case authnStopWords[w]:
			return false
		case strings.HasPrefix(w, "auth") || w == "protect" || authnWords[w]:
			hit = true
		case w == "require" || w == "ensure" || w == "check" || w == "verify" || w == "has":
			sessionGate = true
		case w == "session" || w == "user" || w == "login" || w == "signin":
			if sessionGate {
				hit = true
			}
		}
	}
	return hit
}

var (
	authnWords     = setOf("logged", "jwt", "token", "passport", "bearer", "guard", "signedin", "clerk", "authn", "oauth", "oidc", "keycloak", "firebase", "cognito", "auth0")
	authnStopWords = setOf("optional", "challenge", "challenges", "parse", "parser", "csrf", "refresh", "cookie", "cookies", "maybe", "try", "soft", "populate", "attach", "extract", "decode", "identify", "if", "initialize", "update", "set", "store", "track", "log", "record", "count")
)

// principalWriterRe names middleware that copies the authenticated principal
// into the request (Juice Shop's `appendUserId()` sets req.body.UserId).
var principalWriterRe = regexp.MustCompile(`(?:append|attach|inject|assign|add|set)(?:User|Owner|Tenant|Account|Principal)(?:Id|ID)?\b`)

func writesPrincipal(chain []mwRef) bool {
	for _, m := range chain {
		if principalWriterRe.MatchString(m.text()) {
			return true
		}
	}
	return false
}

// permissionArg: an auth middleware called with a string literal names a
// permission or role (`auth('manageUsers')`, `requireScope('read:x')`), which
// is an authorization decision — except an `authenticate('strategy')` call (passport and its lookalikes).
func permissionArg(code, raw string) bool {
	if authnArgRe.MatchString(code) {
		return false
	}
	open := strings.IndexByte(code, '(')
	if open < 0 || !authnName(code[:open]) {
		return false
	}
	rest := strings.TrimSpace(raw[open+1:])
	return strings.HasPrefix(rest, "'") || strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, "`")
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

func idSources(l label) string {
	var out []string
	if l&lIDPath != 0 {
		out = append(out, "path")
	}
	if l&lIDQuery != 0 {
		out = append(out, "query")
	}
	if l&lIDBody != 0 {
		out = append(out, "body")
	}
	return strings.Join(out, ",")
}

// idSourcePhrase names where the identifier came from, for the message:
// "route path", "query string", "request body", or several joined by "and".
func idSourcePhrase(l label) string {
	var out []string
	if l&lIDPath != 0 {
		out = append(out, "route path")
	}
	if l&lIDQuery != 0 {
		out = append(out, "query string")
	}
	if l&lIDBody != 0 {
		out = append(out, "request body")
	}
	return strings.Join(out, " and ")
}

func newFinding(r *route, h fnRef, sink sinkHit, authn string) findings.Finding {
	framework := "express"
	if bytes.Contains(r.file.raw, []byte("fastify")) && !bytes.Contains(r.file.raw, []byte("express")) {
		framework = "fastify"
	}
	return buildFinding(findingData{
		framework: framework, method: strings.ToUpper(r.method), path: r.path, authn: authn, sink: sink,
		routeFile: r.file.path, routeLine: lineAt(r.file.lineStarts, r.offset),
		handlerFile: h.file.path, line: lineAt(h.file.lineStarts, sink.off), function: h.name,
	})
}

// findingData is what a finding needs, whichever language's reader found it.
type findingData struct {
	framework, method, path, authn string
	sink                           sinkHit
	routeFile                      string
	routeLine                      int
	handlerFile                    string
	line                           int
	function                       string
}

func buildFinding(d findingData) findings.Finding {
	msg := fmt.Sprintf(
		"%s %s requires an authenticated caller (%s) but looks up a record by an id the caller supplies in the %s, via %s(), with no visible check that it belongs to the caller: possible broken object-level authorization (IDOR). Verify by requesting another user's record.",
		d.method, d.path, d.authn, idSourcePhrase(d.sink.idFrom), d.sink.method)
	md := map[string]string{
		"cwe":        "CWE-639",
		"owasp_api":  "API1:2023",
		"route":      d.method + " " + d.path,
		"route_file": d.routeFile,
		"route_line": fmt.Sprintf("%d", d.routeLine),
		"auth":       d.authn,
		"sink":       d.sink.method,
		"model":      d.sink.model,
		"framework":  d.framework,
		"id_source":  idSources(d.sink.idFrom),
	}
	if d.function != "" {
		md["function"] = d.function
	}
	return findings.Finding{
		RuleID:     RuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceLow,
		Location:   findings.Location{FilePath: d.handlerFile, StartLine: d.line, EndLine: d.line},
		Message:    msg,
		Metadata:   md,
	}
}
