package authz

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Next.js route handlers.
//
// Next.js has no route registration to read: the file system is the router.
// `app/api/users/[id]/route.ts` serves /api/users/:id, and the HTTP methods are
// the verbs it exports; `pages/api/users/[id].ts` serves the same path with one
// default-exported handler that branches on `req.method`. This reader turns
// those files into the same Route and routeView the Express and Flask readers
// produce, so AUTHN-001, WEBHOOK-001 and `nox model` see Next.js routes.
//
// What it states, and no more: a route's Authn is set when the handler (the
// file it is exported from) reads the caller's identity or rejects an
// anonymous caller, or when it is exported through a wrapper whose name says it
// authenticates (`export const GET = withAuth(...)`). Next.js middleware
// (middleware.ts) that mentions an auth library is a guard this reader does not
// evaluate against the matcher, so it makes every Next.js route's empty Authn
// proof of nothing (guardUnseen), exactly as a Flask before_request hook does.
//
// What it does not do: AUTHZ-001's body analysis (object-level authorization)
// is not run over these handlers, and a handler's callees are not followed, so
// authentication performed only inside a helper the file imports is not seen.
// Both errors point toward silence, not toward a false lead: an inline read of
// the identity anywhere in the file counts.

var (
	// nextAppRouteRe: app/**/route.(js|ts|...) at the repository root or under
	// src/ (or any directory: a monorepo keeps apps/web/app/...).
	nextAppRouteRe = regexp.MustCompile(`(?:^|/)app/((?:[^/]+/)*)route\.(?:js|jsx|ts|tsx|mjs|mts)$`)
	// nextPagesAPIRe: pages/api/**/x.(js|ts|...).
	nextPagesAPIRe = regexp.MustCompile(`(?:^|/)pages/(api/(?:[^/]+/)*[^/]+)\.(?:js|jsx|ts|tsx|mjs|mts)$`)
	nextMiddleware = regexp.MustCompile(`(?:^|/)middleware\.(?:js|ts|mjs|mts)$`)

	// nextVerbRe finds an exported HTTP verb: `export async function GET(`,
	// `export const POST = `, `export { handler as DELETE }`.
	nextVerbRe = regexp.MustCompile(`export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+(?:const|let|var)\s+(GET|POST|PUT|PATCH|DELETE)\b|\bas\s+(GET|POST|PUT|PATCH|DELETE)\b`)

	// nextExportWrapRe finds the callee an export is wrapped in:
	// `export const GET = withAuth(...)`, `export default auth(handler)`.
	nextExportWrapRe = regexp.MustCompile(`export\s+(?:const\s+(GET|POST|PUT|PATCH|DELETE)\s*=|default)\s*(?:async\s*)?([A-Za-z_$][\w$.]*)\s*\(`)

	// nextMethodRe finds the method a pages/api handler branches on.
	nextMethodEqRe   = regexp.MustCompile(`req\s*\.\s*method\s*===?\s*['"](GET|POST|PUT|PATCH|DELETE)['"]|case\s+['"](GET|POST|PUT|PATCH|DELETE)['"]\s*:`)
	nextMethodOnlyRe = regexp.MustCompile(`req\s*\.\s*method\s*!==?\s*['"](GET|POST|PUT|PATCH|DELETE)['"]`)

	// nextAuthRe reads the caller's identity through the libraries Next.js apps
	// use, beyond what jsInlineAuthRe knows.
	nextAuthRe = regexp.MustCompile(`\bauth\s*\(\s*\)|\bgetToken\s*\(|\bclerkClient\b|\bwithApiAuthRequired\b|\bgetKindeServerSession\b|` +
		`\bsupabase\w*\s*\.\s*auth\s*\.\s*get(?:User|Session)\b|\brequireUser\s*\(|\bverifySession\s*\(|\bvalidateRequest\s*\(|` +
		`\bgetCurrentUser\s*\(|\bgetAuthUser\s*\(|\brequireAuth\s*\(|\bensureAuth\w*\s*\(|\bstatus\s*:\s*40[13]\b|\bverifyIdToken\s*\(|\bjwtVerify\s*\(|\bverifyToken\s*\(`)

	// nextMiddlewareAuthRe: middleware.ts that guards with an auth library.
	nextMiddlewareAuthRe = regexp.MustCompile(`next-auth|@clerk/nextjs|clerkMiddleware|authMiddleware|withAuth\b|@auth0/nextjs-auth0|kinde|@supabase/(?:ssr|auth-helpers)|getToken\s*\(|\bauth\s*\(|lucia|iron-session|jwtVerify|verifyToken`)
)

// nextPath turns a file-system route directory into a route path:
// `(group)` segments vanish, `[id]` becomes :id, `[...rest]` and `[[...rest]]`
// become *rest, and `index` ends a pages route.
func nextPath(segments []string) string {
	var out []string
	for _, s := range segments {
		switch {
		case s == "" || s == "index":
			continue
		case strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")"):
			continue
		case strings.HasPrefix(s, "[[...") && strings.HasSuffix(s, "]]"):
			out = append(out, "*"+s[5:len(s)-2])
		case strings.HasPrefix(s, "[...") && strings.HasSuffix(s, "]"):
			out = append(out, "*"+s[4:len(s)-1])
		case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
			out = append(out, ":"+s[1:len(s)-1])
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// nextRoutes reads every Next.js route handler among the JavaScript files.
func (ix *index) nextRoutes() ([]Route, []routeView) {
	guard := false
	for _, p := range ix.order {
		if nextMiddleware.MatchString(p) && nextMiddlewareAuthRe.MatchString(ix.files[p].sans) {
			guard = true
		}
	}
	var routes []Route
	var views []routeView
	for _, p := range ix.order {
		f := ix.files[p]
		if m := nextAppRouteRe.FindStringSubmatch(p); m != nil {
			rs, vs := nextAppRoutes(f, m[1], guard)
			routes, views = append(routes, rs...), append(views, vs...)
			continue
		}
		if m := nextPagesAPIRe.FindStringSubmatch(p); m != nil {
			rs, vs := nextPagesRoutes(f, m[1], guard)
			routes, views = append(routes, rs...), append(views, vs...)
		}
	}
	return routes, views
}

func nextAppRoutes(f *jsFile, dir string, guard bool) ([]Route, []routeView) {
	verbs := map[string]int{}
	for _, m := range nextVerbRe.FindAllStringSubmatchIndex(f.code, -1) {
		for g := 1; g <= 3; g++ {
			if m[2*g] >= 0 {
				v := f.code[m[2*g]:m[2*g+1]]
				if _, seen := verbs[v]; !seen {
					verbs[v] = m[0]
				}
			}
		}
	}
	if len(verbs) == 0 {
		return nil, nil // a file named route.ts that exports no verb is not a route
	}
	wraps := map[string]string{}
	for _, m := range nextExportWrapRe.FindAllStringSubmatch(f.sans, -1) {
		if m[1] != "" {
			wraps[m[1]] = m[2]
		} else {
			wraps["*"] = m[2]
		}
	}
	routePath := nextPath(strings.Split(strings.Trim(dir, "/"), "/"))
	return nextBuild(f, routePath, verbs, wraps, guard)
}

func nextPagesRoutes(f *jsFile, rel string, guard bool) ([]Route, []routeView) {
	if !strings.Contains(f.sans, "export default") && !strings.Contains(f.sans, "module.exports") {
		return nil, nil // no handler to serve the path
	}
	segs := strings.Split(rel, "/")
	routePath := nextPath(segs)
	verbs := map[string]int{}
	for _, m := range nextMethodEqRe.FindAllStringSubmatchIndex(f.sans, -1) {
		for g := 1; g <= 2; g++ {
			if m[2*g] >= 0 {
				v := f.sans[m[2*g]:m[2*g+1]]
				if _, seen := verbs[v]; !seen {
					verbs[v] = m[0]
				}
			}
		}
	}
	// `if (req.method !== 'POST') return 405` makes the handler POST-only.
	if only := nextMethodOnlyRe.FindStringSubmatchIndex(f.sans); only != nil && len(verbs) == 0 {
		verbs[f.sans[only[2]:only[3]]] = only[0]
	}
	if len(verbs) == 0 {
		verbs["ALL"] = strings.Index(f.sans, "export default")
		if verbs["ALL"] < 0 {
			verbs["ALL"] = 0
		}
	}
	wraps := map[string]string{}
	if m := nextExportWrapRe.FindStringSubmatch(f.sans); len(m) > 1 && m[1] == "" {
		wraps["*"] = m[2]
	}
	return nextBuild(f, routePath, verbs, wraps, guard)
}

// nextBuild makes one Route and routeView per method.
func nextBuild(f *jsFile, routePath string, verbs map[string]int, wraps map[string]string, guard bool) ([]Route, []routeView) {
	methods := make([]string, 0, len(verbs))
	for v := range verbs {
		methods = append(methods, v)
	}
	sort.Strings(methods)
	var routes []Route
	var views []routeView
	for _, v := range methods {
		authn, authz := "", ""
		wrap := wraps[v]
		if wrap == "" {
			wrap = wraps["*"]
		}
		if wrap != "" {
			name := path.Base(strings.ReplaceAll(wrap, ".", "/"))
			if !notAccessControlRe.MatchString(name) {
				if authzMWRe.MatchString(name) {
					authz = wrap + "(...)"
				}
				if authnName(name) {
					authn = wrap + "(...)"
				}
			}
		}
		if authn == "" && authz == "" && (jsInlineAuthRe.MatchString(f.sans) || nextAuthRe.MatchString(f.sans)) {
			authn = inlineAuthLabel
		}
		rt := Route{Method: v, Path: routePath, FilePath: f.path, Line: lineAt(f.lineStarts, verbs[v]), Authn: authn, Authz: authz, Reader: ReaderNextJS}
		routes = append(routes, rt)
		views = append(views, routeView{route: rt, handler: f.sans, known: true, chain: wrap, guardUnseen: guard, framework: "nextjs"})
	}
	return routes, views
}
