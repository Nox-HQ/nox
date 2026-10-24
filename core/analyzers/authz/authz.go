// Package authz is nox's static detector for possible broken object-level
// authorization (BOLA / IDOR — OWASP API1:2023, CWE-639) in Express-style
// JavaScript and TypeScript servers.
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
// WHY OPT-IN. Measured on 22 pinned open-source Express apps (see the PR and
// CHANGELOG for the counts): every finding on the ordinary apps was a real
// authorization defect, but a quarter of the findings on deliberately
// vulnerable apps were resources shared by design (a picture's likes, a
// public profile, a shared product catalogue), a class no reader of source can
// refute, and the ordinary apps that produced findings at all were three.
// That is not enough to put a medium finding in front of every scan, so the
// rule runs when scan.rules.enable names it.
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
// SCOPE. Express (and koa-router, which shares the registration shape) in
// JavaScript and TypeScript. Decorator frameworks (NestJS), Next.js route
// handlers, custom route-definition helpers, handlers that read parameters
// through a validation helper (`parseReq(req, schema)`), lookups keyed by a
// non-id field (username, email, slug), auto-generated REST layers with no
// handler in source, and Python are not read.
package authz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
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
type Analyzer struct {
	enabled   bool
	reasoning *reasoning.Store
}

// RecordReasoningTo directs this analyzer's refutations at store: every route
// that met the proposition's antecedent (authenticated, identifier-keyed
// lookup) and was then cleared by a counterexample is filed with the reason,
// so stage accounting can count AUTHZ candidates against what was refuted.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// NewAnalyzer returns the analyzer. AUTHZ-001 is opt-in: it reports only when
// EnableOptIn names it (scan.rules.enable).
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// EnableOptIn turns AUTHZ-001 on when ids names it.
func (a *Analyzer) EnableOptIn(ids []string) {
	for _, id := range ids {
		if id == RuleID {
			a.enabled = true
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
		Tags:        []string{"authorization", "bola", "idor", "owasp-a01", "express"},
		Remediation: "Scope the lookup to the caller (`WHERE id = $1 AND owner_id = $2` with the principal's id, or `{ where: { id, ownerId: req.user.id } }`), or load the record and reject the request when it does not belong to the caller (`if (doc.ownerId !== req.user.id) return res.sendStatus(404)`), or route it through your policy layer. If the resource is shared by design, waive the finding with that reason. To confirm before changing code: create a record as user A, request it with user B's credentials; a 200 with A's data confirms the finding.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			"https://cwe.mitre.org/data/definitions/639.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
		},
		Metadata: map[string]string{"cwe": "CWE-639", "owasp_api": "API1:2023"},
	})
	return rs
}

// index is the repository's JavaScript/TypeScript as one unit: routes and
// handlers live in different files, and so does the middleware that guards
// them.
type index struct {
	files     map[string]*jsFile
	order     []string
	rls       bool
	reasoning *reasoning.Store
}

var jsExt = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true}

var rlsRe = regexp.MustCompile(`(?i)\benable\s+row\s+level\s+security\b|\bcreate\s+policy\s`)

// ScanArtifacts reports AUTHZ-001 findings. It is deterministic: files are
// read in path order and findings are sorted.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	if !a.enabled {
		return fs, nil
	}
	ix := &index{files: map[string]*jsFile{}, reasoning: a.reasoning}
	rls := false
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
		if art.Type != discovery.Source || !jsExt[ext] || nsource.IsTestPath(art.Path) {
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
		ix.files[p] = &jsFile{path: p, raw: raw, code: string(lexctx.MaskNonCode(lexctx.LangJavaScript, raw)), lineStarts: computeLineStarts(raw)}
		ix.order = append(ix.order, p)
	}
	// Row-level security moves the ownership check into the database, where
	// no handler shows it: every candidate is refuted, and recorded as such.
	ix.rls = rls
	for _, f := range ix.findings() {
		fs.Add(f)
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
		uses[p] = parseUses(f, mount)
		routes = append(routes, parseRoutes(f)...)
		params[p] = parseParamLoaders(f)
	}
	inherited := ix.inheritedMiddleware(uses)

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
	}
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
	ix.reasoning.RefuteWithin(reasoning.Candidate(RuleID, path, line, 1), evidence.KindStatic, "nox-scan", "authz",
		reason, reasoning.Scope{
			Analysis: "the Express route reader, over this repository's JavaScript and TypeScript",
			Limits:   "middleware and policy recognised by name rather than by behaviour, and a check in a callee the request is not visibly passed to",
		})
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
			if authn == "" && unauthorizedRe.MatchString(t) {
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
	line := lineAt(h.file.lineStarts, sink.off)
	routeLine := lineAt(r.file.lineStarts, r.offset)
	method := strings.ToUpper(r.method)
	msg := fmt.Sprintf(
		"%s %s requires an authenticated caller (%s) but looks up a record by an id the caller supplies in the %s, via %s(), with no visible check that it belongs to the caller: possible broken object-level authorization (IDOR). Verify by requesting another user's record.",
		method, r.path, authn, idSourcePhrase(sink.idFrom), sink.method)
	md := map[string]string{
		"cwe":        "CWE-639",
		"owasp_api":  "API1:2023",
		"route":      method + " " + r.path,
		"route_file": r.file.path,
		"route_line": fmt.Sprintf("%d", routeLine),
		"auth":       authn,
		"sink":       sink.method,
		"model":      sink.model,
		"framework":  "express",
		"id_source":  idSources(sink.idFrom),
	}
	if h.name != "" {
		md["function"] = h.name
	}
	return findings.Finding{
		RuleID:     RuleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceLow,
		Location:   findings.Location{FilePath: h.file.path, StartLine: line, EndLine: line},
		Message:    msg,
		Metadata:   md,
	}
}
