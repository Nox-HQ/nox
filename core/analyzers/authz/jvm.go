package authz

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Spring MVC / WebFlux annotated controllers and JAX-RS resources, in Java and
// Kotlin.
//
// A Spring route is an annotation pair: `@RequestMapping("/users")` on a class
// marked `@RestController` or `@Controller`, and `@GetMapping("/{id}")` (or
// `@RequestMapping(method = RequestMethod.X)`) on a method. A JAX-RS route is
// `@Path` on a class and a verb annotation (`@GET`) on a method, optionally
// with its own `@Path`. The annotations are read over the lexically masked
// text with the same member scanner the NestJS reader uses (an annotation is
// a decorator), and produce the same Route and routeView, so AUTHN-001 and
// `nox model` cover them.
//
// What it states, and no more:
//
//   - a route's Authn is set by an annotation on its method or class that makes
//     the caller authenticate (@PreAuthorize, @PostAuthorize, @Secured,
//     @RolesAllowed, @Authenticated, @DenyAll, or one named like an
//     authenticator), by a parameter that carries the caller
//     (@AuthenticationPrincipal, a Principal, Authentication or SecurityContext
//     parameter, Dropwizard's @Auth), or by a read of the caller in the handler
//     (SecurityContextHolder, getUserPrincipal). Handler-level evidence replaces
//     class-level evidence, so a method's own @PermitAll is not covered by its
//     class's @PreAuthorize;
//   - @PermitAll, @PreAuthorize("permitAll()") and the lookalikes mark the
//     route public on purpose, which is intent and never a missing-authentication
//     lead;
//   - applications authenticate globally. When any file of the same project
//     defines a Spring Security filter chain (a SecurityFilterChain bean,
//     HttpSecurity, WebSecurityConfigurerAdapter, @EnableWebSecurity, the
//     WebFlux equivalents, Kotlin's http { authorizeHttpRequests { } }), or a
//     request filter (ContainerRequestFilter, a servlet Filter, a Spring
//     interceptor) not named for logging, CORS and the like, authentication is
//     decided somewhere this reader does not evaluate: a route with no
//     handler-level evidence of its own is guardUnseen, never a lead, and never
//     recorded as authenticated. requestMatchers are not evaluated.
//
// A project is the topmost directory holding a build file (pom.xml,
// build.gradle[.kts]) above the file, so every module of a multi-module build
// shares one security configuration; with no build file it is the parent of
// the file's `src` directory.
//
// Only a file that imports org.springframework. (Spring) or javax/jakarta.ws.rs
// (JAX-RS) is read: `@Controller` and `@GetMapping` also exist in Micronaut,
// Quarkus and others whose security model differs.
//
// What it does not do: a path built from a constant, a concatenation or a
// placeholder (`@GetMapping(Paths.USERS)`, `"${base}/x"`) is not resolved, so
// that route is skipped, not guessed; a controller's context path
// (server.servlet.context-path), JAX-RS resources declared on an interface
// whose implementation carries no annotations, Spring functional routes
// (RouterFunction), Spring Data REST, sub-resource locators and Spring
// Security's XML configuration are not read; and webhook verification is not
// judged, because a handler's delegates are not followed.

var (
	jvmSpringImportRe = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?org\.springframework\.`)
	jvmJAXRSImportRe  = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?(?:javax|jakarta)\.ws\.rs[.;\s]`)
	jvmClassRe        = regexp.MustCompile(`(?:^|[\s)])class\s+([A-Za-z_]\w*)`)
	jvmRequestMethod  = regexp.MustCompile(`\b(?:RequestMethod\s*\.\s*)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b`)
	jvmNamedArgRe     = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=[^=]`)

	// jvmSecurityConfigRe: a Spring Security filter chain, in any of its forms.
	jvmSecurityConfigRe = regexp.MustCompile(`\bSecurityFilterChain\b|\bSecurityWebFilterChain\b|\bHttpSecurity\b|\bServerHttpSecurity\b|\bWebSecurityConfigurerAdapter\b|@EnableWebSecurity\b|@EnableWebFluxSecurity\b|\bauthorize(?:Http)?Requests\s*\{|\bauthorizeExchange\s*\{`)
	// jvmFilterClassRe: a class that intercepts every request.
	jvmFilterClassRe = regexp.MustCompile(`\b(?:class|object)\s+([A-Za-z_]\w*)[^{;]*?\b(?:ContainerRequestFilter|OncePerRequestFilter|GenericFilterBean|HandlerInterceptor|HandlerInterceptorAdapter|WebFilter|Filter)\b`)
	// jvmBenignFilter: request filters that do not decide who the caller is.
	jvmBenignFilter = regexp.MustCompile(`(?i)logging|logger|requestlog|accesslog|cors|trac(?:e|ing)|metric|compress|gzip|correlation|requestid|mdc|timing|csrf|locale|i18n|etag|cache|ratelimit|throttl|encoding|forwarded|xss`)

	jvmApplicationPathRe = regexp.MustCompile(`@ApplicationPath\s*\(`)

	// jvmPrincipalParamRe: a parameter that carries the caller.
	jvmPrincipalParamRe = regexp.MustCompile(`@(?:AuthenticationPrincipal|CurrentSecurityContext|CurrentUser|Auth)\b|\b(?:Principal|Authentication|SecurityContext|UserDetails|OAuth2User|OidcUser|JwtAuthenticationToken)\b`)
	// jvmInlineAuthRe: the handler reads who the caller is.
	jvmInlineAuthRe = regexp.MustCompile(`\bSecurityContextHolder\b|\bReactiveSecurityContextHolder\b|\bgetUserPrincipal\s*\(|\.userPrincipal\b|\bgetRemoteUser\s*\(|\bisUserInRole\s*\(|\bgetAuthentication\s*\(`)

	jvmSpringVerbs = map[string]string{"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE", "PatchMapping": "PATCH"}
	jvmJAXRSVerbs  = map[string]string{"GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE", "PATCH": "PATCH", "HEAD": "HEAD", "OPTIONS": "OPTIONS"}
	// jvmAuthnAnnotations authenticate the caller (and usually authorize).
	jvmAuthnAnnotations = setOf("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll", "Authenticated", "PermissionsAllowed", "PreFilter", "PostFilter")
	// jvmRoutingAnnotations are never access control, whatever they are named.
	jvmRoutingAnnotations = setOf("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "Path", "Produces", "Consumes", "ApplicationPath")
)

// jvmFile is one Java or Kotlin source file, read as masked text.
type jvmFile struct {
	path       string
	raw        []byte
	code       string // lexctx.MaskNonCode(raw)
	sans       string // raw with comments blanked, strings kept
	lineStarts []int
	spring     bool
	jaxrs      bool
}

func newJVMFile(path string, raw []byte) *jvmFile {
	lang := lexctx.LangJava
	if strings.EqualFold(filepath.Ext(path), ".kt") {
		lang = lexctx.LangKotlin
	}
	f := &jvmFile{path: path, raw: raw, code: string(lexctx.MaskNonCode(lang, raw)), sans: withoutComments(lang, raw), lineStarts: computeLineStarts(raw)}
	f.spring = jvmSpringImportRe.MatchString(f.sans)
	f.jaxrs = jvmJAXRSImportRe.MatchString(f.sans)
	return f
}

// jvmScope is what one project declares for the whole application.
type jvmScope struct {
	// guarded: authentication is decided by something this reader does not evaluate.
	guarded bool
	// apiPrefix: JAX-RS @ApplicationPath.
	apiPrefix string
}

type jvmIndex struct {
	files     []*jvmFile
	buildDirs map[string]bool
	scopes    map[string]*jvmScope
	// guardDirs: directories whose files are authenticated by configuration
	// (a dependency, application.properties). Unlike a filter chain, which is
	// code shared by the project, configuration belongs to the module it sits in.
	guardDirs []string
}

// jvmProjectRoot is the topmost build-file directory above file; with none,
// the parent of the file's `src` directory.
func (ix *jvmIndex) projectRoot(file string) string {
	segs := strings.Split(file, "/")
	for i := 0; i < len(segs)-1; i++ {
		dir := strings.Join(segs[:i], "/")
		if ix.buildDirs[dir] {
			return dir
		}
	}
	for i := len(segs) - 2; i >= 0; i-- {
		if segs[i] == "src" {
			return strings.Join(segs[:i], "/")
		}
	}
	return strings.Join(segs[:len(segs)-1], "/")
}

// moduleRoot is the deepest build-file directory above file, or the parent of
// its `src` directory: the module a configuration file belongs to.
func (ix *jvmIndex) moduleRoot(file string) string {
	segs := strings.Split(file, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if dir := strings.Join(segs[:i], "/"); ix.buildDirs[dir] {
			return dir
		}
	}
	return ix.projectRoot(file)
}

// guardedByConfiguration: file sits in, or under, a module configured to
// authenticate every request.
func (ix *jvmIndex) guardedByConfiguration(file string) bool {
	for _, d := range ix.guardDirs {
		if d == "" || strings.HasPrefix(file, d+"/") {
			return true
		}
	}
	return false
}

func (ix *jvmIndex) scopeOf(root string) *jvmScope {
	s := ix.scopes[root]
	if s == nil {
		s = &jvmScope{}
		ix.scopes[root] = s
	}
	return s
}

func newJVMIndex(files []*jvmFile, buildDirs map[string]bool, guardFiles []string) *jvmIndex {
	ix := &jvmIndex{files: files, buildDirs: buildDirs, scopes: map[string]*jvmScope{}}
	for _, g := range guardFiles {
		ix.guardDirs = append(ix.guardDirs, ix.moduleRoot(g))
	}
	for _, f := range files {
		root := ix.projectRoot(f.path)
		if f.spring && jvmSecurityConfigRe.MatchString(f.code) {
			ix.scopeOf(root).guarded = true
		}
		for _, m := range jvmFilterClassRe.FindAllStringSubmatch(f.code, -1) {
			if !jvmBenignFilter.MatchString(m[1]) {
				ix.scopeOf(root).guarded = true
			}
		}
		if f.jaxrs {
			for _, loc := range jvmApplicationPathRe.FindAllStringIndex(f.code, -1) {
				if end := matchClose(f.code, loc[1]-1); end > 0 {
					if v, ok := stringLiteral(f.raw, f.code, trimSpan(f.code, span{loc[1], end})); ok {
						ix.scopeOf(root).apiPrefix = v
					}
				}
			}
		}
	}
	return ix
}

// jvmRoutes reads every Spring controller and JAX-RS resource.
func (ix *jvmIndex) routes() ([]Route, []routeView) {
	var routes []Route
	var views []routeView
	for _, f := range ix.files {
		if !f.spring && !f.jaxrs {
			continue
		}
		scope := ix.scopes[ix.projectRoot(f.path)]
		if ix.guardedByConfiguration(f.path) {
			scope = &jvmScope{guarded: true, apiPrefix: scopeAPIPrefix(scope)}
		}
		for _, c := range nestScan(f.code, 0, len(f.code)) {
			rs, vs := jvmClass(f, c, scope)
			routes, views = append(routes, rs...), append(views, vs...)
		}
	}
	return routes, views
}

func jvmAnnotationName(d nestDecorator) string {
	if i := strings.LastIndexByte(d.name, '.'); i >= 0 {
		return d.name[i+1:]
	}
	return d.name
}

// jvmEvidence is what the annotations and parameters of one class or method
// say about who may call it.
type jvmEvidence struct {
	authn  string
	public bool
}

func (e jvmEvidence) any() bool { return e.authn != "" || e.public }

func jvmApplyAnnotation(f *jvmFile, d nestDecorator, e *jvmEvidence) {
	name := jvmAnnotationName(d)
	if jvmRoutingAnnotations[name] || jvmSpringVerbs[name] != "" || jvmJAXRSVerbs[name] != "" {
		return
	}
	args := ""
	if d.hasArgs {
		args = f.sans[d.args.start:d.args.end]
	}
	switch {
	case name == "PermitAll" || nestPublicRe.MatchString(name):
		e.public = true
	case (name == "PreAuthorize" || name == "PostAuthorize") && jvmPublicExprRe.MatchString(args):
		e.public = true
	case name == "Secured" && strings.Contains(args, "IS_AUTHENTICATED_ANONYMOUSLY"):
		e.public = true
	case jvmAuthnAnnotations[name] || authnName(name):
		if e.authn == "" {
			e.authn = "@" + name
		}
	}
}

// jvmPublicExprRe: a method-security expression that lets everyone in.
var jvmPublicExprRe = regexp.MustCompile(`\bpermitAll\b|\bisAnonymous\b`)

// jvmParams returns the text between a signature's first parenthesis and its
// match: the parameter list, with its annotations.
func jvmParams(f *jvmFile, m nestMember) string {
	rel := strings.IndexByte(f.code[m.start:m.end], '(')
	if rel < 0 {
		return ""
	}
	open := m.start + rel
	end := matchClose(f.code, open)
	if end < 0 || end > m.end {
		return ""
	}
	return f.sans[open:end]
}

// jvmStrings reads a path attribute: one literal, or an array of literals
// (`{"/a", "/b"}` in Java, `["/a"]` or arrayOf("/a") in Kotlin). ok is false
// when any element is not a literal this reader can read.
func jvmStrings(f *jvmFile, s span) ([]string, bool) {
	s = trimSpan(f.code, s)
	if s.end <= s.start {
		return nil, false
	}
	one := func(e span) (string, bool) {
		v, ok := stringLiteral(f.raw, f.code, e)
		if !ok || strings.Contains(v, "$") {
			return "", false
		}
		return v, true
	}
	if v, ok := one(s); ok {
		return []string{v}, true
	}
	open := s.start
	if rest := f.code[s.start:s.end]; strings.HasPrefix(rest, "arrayOf") || strings.HasPrefix(rest, "listOf") {
		open = s.start + strings.IndexByte(rest, '(')
	} else if f.code[s.start] != '{' && f.code[s.start] != '[' {
		return nil, false
	}
	end := matchClose(f.code, open)
	if end < 0 || end != s.end-1 {
		return nil, false
	}
	var out []string
	for _, e := range splitArgs(f.code, open+1, end) {
		v, ok := one(e)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return []string{""}, true
	}
	return out, true
}

// jvmAttr finds an annotation attribute by name; a lone positional argument
// stands for `value`.
func jvmAttr(f *jvmFile, d nestDecorator, names ...string) (span, bool) {
	if !d.hasArgs {
		return span{}, false
	}
	for i, a := range splitArgs(f.code, d.args.start, d.args.end) {
		text := f.code[a.start:a.end]
		if m := jvmNamedArgRe.FindStringSubmatch(text); m != nil {
			for _, n := range names {
				if m[1] == n {
					return trimSpan(f.code, span{a.start + strings.IndexByte(text, '=') + 1, a.end}), true
				}
			}
			continue
		}
		if i == 0 {
			for _, n := range names {
				if n == "value" {
					return a, true
				}
			}
		}
	}
	return span{}, false
}

// jvmPaths is an annotation's path: none (""), or its literals. ok is false
// when it names a path this reader cannot read.
func jvmPaths(f *jvmFile, d nestDecorator) ([]string, bool) {
	s, found := jvmAttr(f, d, "value", "path")
	if !found {
		return []string{""}, true
	}
	return jvmStrings(f, s)
}

func jvmJoin(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p = strings.Trim(p, "/"); p != "" {
			kept = append(kept, p)
		}
	}
	return "/" + strings.Join(kept, "/")
}

func jvmClass(f *jvmFile, c nestMember, scope *jvmScope) ([]Route, []routeView) {
	if c.body < 0 {
		return nil, nil
	}
	cm := jvmClassRe.FindStringSubmatch(f.code[c.start:c.body])
	if cm == nil {
		return nil, nil
	}
	end := matchClose(f.code, c.body)
	if end < 0 {
		return nil, nil
	}
	var controller bool
	var mapping, path *nestDecorator
	var classEv jvmEvidence
	for i := range c.decos {
		d := c.decos[i]
		switch jvmAnnotationName(d) {
		case "RestController", "Controller":
			controller = f.spring
		case "RequestMapping":
			mapping = &c.decos[i]
		case "Path":
			path = &c.decos[i]
		}
		jvmApplyAnnotation(f, d, &classEv)
	}
	switch {
	case controller:
		return jvmMembers(f, c, end, scope, classEv, ReaderSpring, "spring", springPrefixes(f, mapping))
	case path != nil && f.jaxrs:
		prefixes, ok := jvmPaths(f, *path)
		if !ok {
			return nil, nil
		}
		return jvmMembers(f, c, end, scope, classEv, ReaderJAXRS, "jaxrs", withAPIPrefix(prefixes, scope))
	}
	return nil, nil
}

type jvmPrefixes struct {
	paths []string
	ok    bool
}

func springPrefixes(f *jvmFile, mapping *nestDecorator) jvmPrefixes {
	if mapping == nil {
		return jvmPrefixes{paths: []string{""}, ok: true}
	}
	paths, ok := jvmPaths(f, *mapping)
	return jvmPrefixes{paths: paths, ok: ok}
}

func scopeAPIPrefix(s *jvmScope) string {
	if s == nil {
		return ""
	}
	return s.apiPrefix
}

func withAPIPrefix(paths []string, scope *jvmScope) jvmPrefixes {
	if scope != nil && scope.apiPrefix != "" {
		for i := range paths {
			paths[i] = jvmJoin(scope.apiPrefix, paths[i])
		}
	}
	return jvmPrefixes{paths: paths, ok: true}
}

func jvmMembers(f *jvmFile, c nestMember, end int, scope *jvmScope, classEv jvmEvidence, reader, framework string, prefixes jvmPrefixes) ([]Route, []routeView) {
	if !prefixes.ok {
		return nil, nil // @RequestMapping(Paths.X): not resolved, not guessed
	}
	var routes []Route
	var views []routeView
	for _, m := range nestScan(f.code, c.body+1, end) {
		verbs, ownPaths, ev := jvmMethodAnnotations(f, m, reader)
		if len(verbs) == 0 || !ownPaths.ok || !strings.Contains(f.code[m.start:m.end], "(") {
			continue
		}
		if !ev.any() {
			ev = classEv
		}
		handler := f.sans[m.start:m.end]
		if ev.authn == "" && !ev.public && (jvmPrincipalParamRe.MatchString(jvmParams(f, m)) || jvmInlineAuthRe.MatchString(handler)) {
			ev.authn = inlineAuthLabel
		}
		guarded := scope != nil && scope.guarded && !ev.public
		for _, vd := range verbs {
			method := vd.method
			for _, pre := range prefixes.paths {
				for _, own := range ownPaths.paths {
					rt := Route{Method: method, Path: jvmJoin(pre, own), FilePath: f.path, Line: lineAt(f.lineStarts, vd.at), Authn: ev.authn, Reader: reader}
					routes = append(routes, rt)
					views = append(views, routeView{route: rt, handler: handler, chain: jvmChain(f, m), guardUnseen: guarded, declaredPublic: ev.public, framework: framework})
				}
			}
		}
	}
	return routes, views
}

type jvmVerb struct {
	method string
	at     int // offset of the verb annotation
}

// jvmMethodAnnotations reads a member's verbs, its own path and its evidence.
func jvmMethodAnnotations(f *jvmFile, m nestMember, reader string) ([]jvmVerb, jvmPrefixes, jvmEvidence) {
	var verbs []jvmVerb
	var ev jvmEvidence
	own := jvmPrefixes{paths: []string{""}, ok: true}
	for _, d := range m.decos {
		name := jvmAnnotationName(d)
		switch {
		case reader == ReaderSpring && jvmSpringVerbs[name] != "":
			verbs = append(verbs, jvmVerb{jvmSpringVerbs[name], d.start})
			own = springOwn(f, d)
		case reader == ReaderSpring && name == "RequestMapping":
			own = springOwn(f, d)
			for _, method := range requestMethods(f, d) {
				verbs = append(verbs, jvmVerb{method, d.start})
			}
		case reader == ReaderJAXRS && jvmJAXRSVerbs[name] != "":
			verbs = append(verbs, jvmVerb{jvmJAXRSVerbs[name], d.start})
		case reader == ReaderJAXRS && name == "Path":
			paths, ok := jvmPaths(f, d)
			own = jvmPrefixes{paths: paths, ok: ok}
		}
		jvmApplyAnnotation(f, d, &ev)
	}
	return verbs, own, ev
}

func springOwn(f *jvmFile, d nestDecorator) jvmPrefixes {
	paths, ok := jvmPaths(f, d)
	return jvmPrefixes{paths: paths, ok: ok}
}

// requestMethods reads `method = RequestMethod.X` (or an array of them); with
// no method attribute the mapping answers every verb.
func requestMethods(f *jvmFile, d nestDecorator) []string {
	s, found := jvmAttr(f, d, "method")
	if !found {
		return []string{"ALL"}
	}
	var out []string
	for _, m := range jvmRequestMethod.FindAllStringSubmatch(f.sans[s.start:s.end], -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		return []string{"ALL"}
	}
	return out
}

// jvmChain is the text of the annotations written before a member.
func jvmChain(f *jvmFile, m nestMember) string {
	if len(m.decos) == 0 {
		return ""
	}
	return f.sans[m.decos[0].start:m.start]
}

var (
	// jvmBuildGuardRe: a dependency that makes Spring Boot authenticate every
	// endpoint on its own, with no configuration class at all.
	jvmBuildGuardRe = regexp.MustCompile(`spring-boot-starter-security|spring-boot-starter-oauth2-(?:resource-server|client|authorization-server)|spring-security-(?:web|config|oauth2-resource-server)\b`)
	// jvmQuarkusGuardRe: Quarkus authenticates by configuration: permission
	// checks on paths, the Keycloak policy enforcer, or denying every endpoint
	// that carries no security annotation.
	jvmQuarkusGuardRe        = regexp.MustCompile(`(?m)^\s*quarkus\.http\.auth\.(?:permission|policy)\.|^\s*quarkus\.keycloak\.policy-enforcer\.enable\s*=\s*true|^\s*quarkus\.security\.jaxrs\.(?:deny-unannotated-endpoints\s*=\s*true|default-roles-allowed)`)
	jvmQuarkusYAMLAuthRe     = regexp.MustCompile(`(?m)^[ \t]+auth:[ \t]*$`)
	jvmQuarkusYAMLPermRe     = regexp.MustCompile(`(?m)^[ \t]+(?:permission|policy):[ \t]*$|^[ \t]+policy-enforcer:[ \t]*$`)
	jvmQuarkusYAMLEnforcerRe = regexp.MustCompile(`(?m)^[ \t]+policy-enforcer:`)
	jvmQuarkusYAMLEnableRe   = regexp.MustCompile(`enable:\s*true`)
	jvmQuarkusYAMLQuarkus    = regexp.MustCompile(`(?m)^quarkus:`)
)

// isJVMConfigFile: an application.properties or application.yml.
func isJVMConfigFile(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "application") {
		return false
	}
	switch filepath.Ext(base) {
	case ".properties", ".yml", ".yaml":
		return true
	}
	return false
}

// jvmConfigGuards reports whether a build or configuration file makes the
// application authenticate every request without any code showing it.
func jvmConfigGuards(path string, raw []byte) bool {
	text := string(raw)
	if isJVMBuildFile(path) {
		return jvmBuildGuardRe.MatchString(text)
	}
	if filepath.Ext(path) == ".properties" {
		return jvmQuarkusGuardRe.MatchString(text)
	}
	if !jvmQuarkusYAMLQuarkus.MatchString(text) {
		return false
	}
	return jvmQuarkusYAMLAuthRe.MatchString(text) && jvmQuarkusYAMLPermRe.MatchString(text) ||
		jvmQuarkusYAMLEnforcerRe.MatchString(text) && jvmQuarkusYAMLEnableRe.MatchString(text)
}

// isJVMBuildFile: a file whose directory is a project root.
func isJVMBuildFile(path string) bool {
	switch filepath.Base(path) {
	case "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts":
		return true
	}
	return false
}

func jvmDir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return ""
}
