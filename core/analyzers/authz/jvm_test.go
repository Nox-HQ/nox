package authz

import (
	"slices"
	"testing"
)

const (
	springHead = "package app;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.security.access.prepost.PreAuthorize;\n"
	jaxrsHead  = "package app;\nimport jakarta.ws.rs.*;\n"
	ktHead     = "package app\n\nimport org.springframework.web.bind.annotation.*\n\n"

	securityChain = "package app;\nimport org.springframework.security.web.SecurityFilterChain;\nimport org.springframework.security.config.annotation.web.builders.HttpSecurity;\n" +
		"@Configuration\npublic class SecurityConfig {\n  @Bean\n  SecurityFilterChain chain(HttpSecurity http) throws Exception {\n    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n  }\n}\n"
)

func javaCtl(t string) map[string]string {
	return map[string]string{"src/main/java/app/UserController.java": springHead + t}
}

func withFile(m map[string]string, name, body string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	out[name] = body
	return out
}

func routeReaders(a *Analyzer) map[string]string {
	out := map[string]string{}
	for _, r := range a.Routes() {
		out[r.Method+" "+r.Path] = r.Reader
	}
	return out
}

func TestSpringRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"prefix and verbs", javaCtl(`@RestController
@RequestMapping("/users")
public class UserController {
  @GetMapping("/{id}") public User get(@PathVariable Long id) { return null; }
  @PostMapping public User create() { return null; }
  @PutMapping("/{id}") public void put() {}
  @DeleteMapping(value = "/{id}") public void del() {}
  @PatchMapping(path = "/{id}/name") public void patch() {}
}`), []string{"DELETE /users/{id}", "GET /users/{id}", "PATCH /users/{id}/name", "POST /users", "PUT /users/{id}"}},
		{"request mapping with method attribute", javaCtl(`@Controller
public class C {
  @RequestMapping(value = "/a", method = RequestMethod.POST)
  public String a() { return ""; }
  @RequestMapping(path = "/b", method = {RequestMethod.GET, RequestMethod.PUT})
  public String b() { return ""; }
  @RequestMapping("/c") public String c() { return ""; }
}`), []string{"ALL /c", "GET /b", "POST /a", "PUT /b"}},
		{"arrays of paths and multi-line annotations", javaCtl(`@RestController
@RequestMapping(
    value = {"/v1", "/v2"}
)
public class C {
  @GetMapping(
      path = { "/x", "/y" },
      produces = "application/json")
  public String x() { return ""; }
}`), []string{"GET /v1/x", "GET /v1/y", "GET /v2/x", "GET /v2/y"}},
		{"fully qualified-free kotlin", map[string]string{"src/main/kotlin/app/C.kt": ktHead + `@RestController
@RequestMapping("/items")
class ItemController(private val svc: ItemService) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): Item = svc.get(id)

    @DeleteMapping("/{id}")
    fun delete(@PathVariable id: Long) {
        svc.delete(id)
    }

    @PostMapping(value = ["/a", "/b"])
    fun create() = svc.create()
}
`}, []string{"DELETE /items/{id}", "GET /items/{id}", "POST /items/a", "POST /items/b"}},
		{"constant path is not guessed", javaCtl(`@RestController
public class C {
  @GetMapping(Paths.USERS) public String a() { return ""; }
  @GetMapping("/ok") public String b() { return ""; }
  @GetMapping("${app.base}/c") public String c() { return ""; }
}`), []string{"GET /ok"}},
		{"not a spring import", map[string]string{"src/main/java/app/C.java": "package app;\nimport io.micronaut.http.annotation.*;\n@Controller(\"/x\")\npublic class C {\n  @Get(\"/y\") public String y() { return \"\"; }\n  @GetMapping(\"/z\") public String z() { return \"\"; }\n}\n"}, nil},
		{"class without a controller annotation", javaCtl(`public class Helper {
  @GetMapping("/z") public String z() { return ""; }
}`), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for k, r := range routeReaders(a) {
				if r != ReaderSpring {
					t.Errorf("%s Reader = %q, want %q", k, r, ReaderSpring)
				}
			}
			if a.RoutesRead() != len(a.Routes()) {
				t.Errorf("RoutesRead %d != %d", a.RoutesRead(), len(a.Routes()))
			}
		})
	}
}

func TestSpringRouteCarriesFileAndLine(t *testing.T) {
	a, _ := scanFiles(t, javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\")\n  public void d() {}\n}\n"))
	rs := a.Routes()
	if len(rs) != 1 || rs[0].FilePath != "src/main/java/app/UserController.java" || rs[0].Line != 6 {
		t.Fatalf("routes = %+v", rs)
	}
}

// Same controller, one thing different at a time.
func TestSpringMissingAuthenticationLeads(t *testing.T) {
	del := "@RestController\n@RequestMapping(\"/users\")\npublic class UserController {\n  @DeleteMapping(\"/{id}\") public void remove(@PathVariable Long id) {}\n}\n"
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no evidence, no global config", javaCtl(del), []string{"DELETE /users/{id}"}},
		{"put and patch", javaCtl("@RestController\npublic class C {\n  @PutMapping(\"/users/{id}\") public void p() {}\n  @PatchMapping(\"/users/{id}\") public void q() {}\n}\n"),
			[]string{"PATCH /users/{id}", "PUT /users/{id}"}},
		{"admin path on a GET", javaCtl("@RestController\npublic class C {\n  @GetMapping(\"/admin/report\") public String r() { return \"\"; }\n}\n"),
			[]string{"GET /admin/report"}},
		{"a sibling's annotation does not cover the route", javaCtl("@RestController\npublic class C {\n  @PreAuthorize(\"hasRole('A')\") @GetMapping(\"/a\") public String a() { return \"\"; }\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"),
			[]string{"DELETE /users/{id}"}},
		{"another controller's class annotation does not cover it", map[string]string{
			"src/main/java/app/A.java": springHead + "@RestController\n@PreAuthorize(\"isAuthenticated()\")\npublic class A {\n  @DeleteMapping(\"/a/{id}\") public void d() {}\n}\n",
			"src/main/java/app/B.java": springHead + "@RestController\npublic class B {\n  @DeleteMapping(\"/b/{id}\") public void d() {}\n}\n"},
			[]string{"DELETE /b/{id}"}},
		{"a principal parameter on a sibling does not cover it", javaCtl("@RestController\npublic class C {\n  @GetMapping(\"/me\") public String me(java.security.Principal p) { return \"\"; }\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"),
			[]string{"DELETE /users/{id}"}},
		{"kotlin", map[string]string{"src/main/kotlin/app/C.kt": ktHead + "@RestController\nclass C {\n    @DeleteMapping(\"/users/{id}\")\n    fun d(@PathVariable id: Long) {}\n}\n"},
			[]string{"DELETE /users/{id}"}},
		{"principal and security context named only in comments", javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d(/* Principal p */) {\n    // SecurityContextHolder.getContext()\n  }\n}\n"),
			[]string{"DELETE /users/{id}"}},
		{"two apps without build files, security in the other", map[string]string{
			"a/src/main/java/app/C.java":        springHead + del,
			"b/src/main/java/app/Security.java": securityChain},
			[]string{"DELETE /users/{id}"}},
		{"micronaut annotations are not spring's", map[string]string{"src/main/java/app/C.java": "package app;\nimport io.micronaut.http.annotation.*;\n@Controller(\"/users\")\npublic class C {\n  @Delete(\"/{id}\") public void d() {}\n  @DeleteMapping(\"/x/{id}\") public void e() {}\n}\n"},
			nil},
		{"preauthorize in a comment is not evidence", javaCtl("@RestController\npublic class C {\n  // @PreAuthorize(\"hasRole('A')\")\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"),
			[]string{"DELETE /users/{id}"}},
		{"security config only in a test tree", withFile(javaCtl(del), "src/test/java/app/TestSecurity.java", securityChain),
			[]string{"DELETE /users/{id}"}},
		{"security config in an unrelated project", map[string]string{
			"a/pom.xml": "<project/>", "b/pom.xml": "<project/>",
			"a/src/main/java/app/C.java":        springHead + del,
			"b/src/main/java/app/Security.java": securityChain},
			[]string{"DELETE /users/{id}"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v (routes %v)", got, c.want, routeKeys(a))
			}
		})
	}
}

func TestSpringSafeVariantsAreNotLeads(t *testing.T) {
	del := "  @DeleteMapping(\"/users/{id}\") public void remove() {}\n}\n"
	cls := func(ann string) map[string]string {
		return javaCtl("@RestController\n" + ann + "\npublic class C {\n" + del)
	}
	meth := func(ann string) map[string]string {
		return javaCtl("@RestController\npublic class C {\n  " + ann + "\n" + del)
	}
	cases := map[string]map[string]string{
		"method @PreAuthorize":  meth("@PreAuthorize(\"hasRole('ADMIN')\")"),
		"class @PreAuthorize":   cls("@PreAuthorize(\"isAuthenticated()\")"),
		"@PostAuthorize":        meth("@PostAuthorize(\"returnObject.owner == authentication.name\")"),
		"@Secured":              meth("@Secured(\"ROLE_ADMIN\")"),
		"class @Secured":        cls("@Secured({\"ROLE_A\", \"ROLE_B\"})"),
		"@RolesAllowed":         meth("@RolesAllowed(\"admin\")"),
		"class @RolesAllowed":   cls("@RolesAllowed({\"admin\"})"),
		"@DenyAll":              meth("@DenyAll"),
		"@PermitAll is public":  meth("@PermitAll"),
		"class @PermitAll":      cls("@PermitAll"),
		"permitAll expression":  meth("@PreAuthorize(\"permitAll()\")"),
		"isAnonymous":           meth("@PreAuthorize(\"isAnonymous()\")"),
		"public-named":          meth("@Public"),
		"authn-named custom":    meth("@RequiresAuthentication"),
		"principal annotation":  javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d(@AuthenticationPrincipal UserDetails u) {}\n}\n"),
		"principal type":        javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d(java.security.Principal p) {}\n}\n"),
		"authentication type":   javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d(Authentication auth) {}\n}\n"),
		"security context read": javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d() { var a = SecurityContextHolder.getContext().getAuthentication(); }\n}\n"),
		"kotlin principal":      {"src/main/kotlin/app/C.kt": ktHead + "@RestController\nclass C {\n    @DeleteMapping(\"/users/{id}\")\n    fun d(principal: Principal) {}\n}\n"},
		"kotlin preauthorize":   {"src/main/kotlin/app/C.kt": ktHead + "@RestController\nclass C {\n    @PreAuthorize(\"hasRole('A')\")\n    @DeleteMapping(\"/users/{id}\")\n    fun d() {}\n}\n"},
		"filter chain bean":     withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/java/app/SecurityConfig.java", securityChain),
		"filter chain in another module of the same project": {
			"pom.xml": "<project/>", "api/pom.xml": "<project/>", "web/pom.xml": "<project/>",
			"api/src/main/java/app/C.java":        springHead + "@RestController\npublic class C {\n" + del,
			"web/src/main/java/app/Security.java": securityChain},
		"WebSecurityConfigurerAdapter": withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/java/app/S.java",
			"import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;\n@Configuration\n@EnableWebSecurity\npublic class S extends WebSecurityConfigurerAdapter {\n  protected void configure(HttpSecurity http) {}\n}\n"),
		"kotlin dsl": withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/kotlin/app/S.kt",
			"package app\nimport org.springframework.security.config.annotation.web.invoke\n@Configuration\nclass S {\n  @Bean\n  fun chain(http: HttpSecurity): SecurityFilterChain {\n    http {\n      authorizeHttpRequests { authorize(anyRequest, authenticated) }\n    }\n    return http.build()\n  }\n}\n"),
		"webflux chain": withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/java/app/S.java",
			"import org.springframework.security.config.web.server.ServerHttpSecurity;\n@Configuration\n@EnableWebFluxSecurity\npublic class S {\n  @Bean SecurityWebFilterChain c(ServerHttpSecurity http) { return http.build(); }\n}\n"),
		"auth servlet filter": withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/java/app/JwtFilter.java",
			"public class JwtFilter extends OncePerRequestFilter {\n  protected void doFilterInternal(HttpServletRequest r, HttpServletResponse s, FilterChain c) {}\n}\n"),
		"auth interceptor": withFile(javaCtl("@RestController\npublic class C {\n"+del), "src/main/java/app/TokenInterceptor.java",
			"public class TokenInterceptor implements HandlerInterceptor {\n  public boolean preHandle(HttpServletRequest r, HttpServletResponse s, Object h) { return true; }\n}\n"),
		"test fixture": {"src/test/java/app/C.java": springHead + "@RestController\npublic class C {\n" + del},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("a safe variant produced leads %v (routes %v)", got, routeKeys(a))
			}
		})
	}
}

// Silence from a global filter chain is not the same as authentication:
// the route must still be read, and must not claim it.
func TestSpringGlobalConfigIsUnseenNotClaimed(t *testing.T) {
	files := withFile(javaCtl("@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"), "src/main/java/app/SecurityConfig.java", securityChain)
	a, _ := scanFiles(t, files)
	rs := a.Routes()
	if len(rs) != 1 {
		t.Fatalf("routes = %v", rs)
	}
	if rs[0].Authn != "" {
		t.Errorf("Authn = %q: the chain is not evaluated, so no route may claim it", rs[0].Authn)
	}
}

// A public route claims no authentication, whatever else sits on it.
func TestSpringPublicRoutesClaimNoAuthentication(t *testing.T) {
	for name, ann := range map[string]string{"PermitAll": "@PermitAll", "permitAll expression": "@PreAuthorize(\"permitAll()\")", "isAnonymous": "@PreAuthorize(\"isAnonymous()\")"} {
		a, _ := scanFiles(t, javaCtl("@RestController\n@PreAuthorize(\"isAuthenticated()\")\npublic class C {\n  "+ann+"\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"))
		rs := a.Routes()
		if len(rs) != 1 || rs[0].Authn != "" {
			t.Errorf("%s: routes = %+v, want one route with no Authn", name, rs)
		}
	}
}

func TestSpringHandlerEvidenceOverridesClass(t *testing.T) {
	a, _ := scanFiles(t, javaCtl(`@RestController
@PreAuthorize("isAuthenticated()")
public class C {
  @PermitAll
  @DeleteMapping("/users/open/{id}") public void open() {}
  @DeleteMapping("/users/closed/{id}") public void closed() {}
}`))
	for _, r := range a.Routes() {
		switch r.Path {
		case "/users/open/{id}":
			if r.Authn != "" {
				t.Errorf("a @PermitAll route must not inherit the class's authentication: %q", r.Authn)
			}
		case "/users/closed/{id}":
			if r.Authn == "" {
				t.Error("the class-level @PreAuthorize must reach a method with no annotation of its own")
			}
		}
	}
	if got := authnLeads(a); len(got) != 0 {
		t.Errorf("public on purpose is intent, not a lead: %v", got)
	}
}

func TestJAXRSRouteTable(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{
		"src/main/java/app/App.java": "package app;\nimport jakarta.ws.rs.ApplicationPath;\nimport jakarta.ws.rs.core.Application;\n@ApplicationPath(\"/api\")\npublic class App extends Application {}\n",
		"src/main/java/app/Users.java": jaxrsHead + `@Path("/users")
public class Users {
  @GET @Path("/{id}") public String get(@PathParam("id") String id) { return ""; }
  @POST public void create() {}
  @PUT @Path("{id}") public void put() {}
  @DELETE @Path("/{id}") public void del() {}
  @PATCH @Path("/{id}/x") public void patch() {}
  @Path("/sub") public Object locator() { return null; }
}`,
	})
	want := []string{"DELETE /api/users/{id}", "GET /api/users/{id}", "PATCH /api/users/{id}/x", "POST /api/users", "PUT /api/users/{id}"}
	if got := routeKeys(a); !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for k, r := range routeReaders(a) {
		if r != ReaderJAXRS {
			t.Errorf("%s Reader = %q", k, r)
		}
	}
}

func TestJAXRSKotlinRoutes(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{"src/main/kotlin/app/R.kt": "package app\n\nimport javax.ws.rs.*\n\n@Path(\"/things\")\nclass R {\n    @GET\n    @Path(\"/{id}\")\n    fun get(@PathParam(\"id\") id: String): String = id\n\n    @DELETE\n    @Path(\"/{id}\")\n    fun del(@PathParam(\"id\") id: String) {}\n}\n"})
	if got, want := routeKeys(a), []string{"DELETE /things/{id}", "GET /things/{id}"}; !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}

func TestJAXRSMissingAuthentication(t *testing.T) {
	del := "@Path(\"/users\")\npublic class Users {\n"
	meth := "  @DELETE @Path(\"/{id}\") public void del(@PathParam(\"id\") String id) {}\n}\n"
	file := func(body string) map[string]string {
		return map[string]string{"src/main/java/app/Users.java": jaxrsHead + body}
	}
	t.Run("lead", func(t *testing.T) {
		a, _ := scanFiles(t, file(del+meth))
		if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
			t.Fatalf("leads = %v", got)
		}
	})
	safe := map[string]map[string]string{
		"method @RolesAllowed":  file(del + "  @RolesAllowed(\"admin\") @DELETE @Path(\"/{id}\") public void d() {}\n}\n"),
		"class @RolesAllowed":   file("@RolesAllowed(\"admin\")\n" + del + meth),
		"@Authenticated":        file(del + "  @Authenticated @DELETE @Path(\"/{id}\") public void d() {}\n}\n"),
		"@PermitAll":            file(del + "  @PermitAll @DELETE @Path(\"/{id}\") public void d() {}\n}\n"),
		"@DenyAll":              file(del + "  @DenyAll @DELETE @Path(\"/{id}\") public void d() {}\n}\n"),
		"SecurityContext param": file(del + "  @DELETE @Path(\"/{id}\") public void d(@Context SecurityContext sc) {}\n}\n"),
		"dropwizard @Auth":      file(del + "  @DELETE @Path(\"/{id}\") public void d(@Auth User user) {}\n}\n"),
		"request filter": withFile(file(del+meth), "src/main/java/app/AuthFilter.java",
			"@Provider\npublic class AuthFilter implements ContainerRequestFilter {\n  public void filter(ContainerRequestContext c) {}\n}\n"),
		"kotlin request filter": withFile(file(del+meth), "src/main/kotlin/app/AuthFilter.kt",
			"@Provider\nclass AuthFilter : ContainerRequestFilter {\n  override fun filter(c: ContainerRequestContext) {}\n}\n"),
		"servlet filter": withFile(file(del+meth), "src/main/java/app/TokenFilter.java",
			"public class TokenFilter implements javax.servlet.Filter {\n  public void doFilter(ServletRequest r, ServletResponse s, FilterChain c) {}\n}\n"),
	}
	for name, files := range safe {
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("safe variant produced leads %v", got)
			}
		})
	}
	t.Run("a logging filter is not authentication", func(t *testing.T) {
		a, _ := scanFiles(t, withFile(file(del+meth), "src/main/java/app/LoggingFilter.java",
			"@Provider\npublic class LoggingFilter implements ContainerRequestFilter {\n  public void filter(ContainerRequestContext c) {}\n}\n"))
		if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
			t.Fatalf("leads = %v", got)
		}
	})
}

func TestJVMReadersLeaveOtherLanguagesAlone(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{"app.py": "print('hi')\n", "src/Foo.java": "package a;\npublic class Foo { public static void main(String[] a) {} }\n"})
	if len(a.Routes()) != 0 {
		t.Fatalf("routes = %v", a.Routes())
	}
}

// An application can authenticate by configuration alone: Spring Boot secures
// every endpoint once spring-boot-starter-security is a dependency, and Quarkus
// by quarkus.http.auth.permission.* or its policy enforcer. The same resource
// with and without that configuration differs by exactly that one file.
func TestJVMConfigurationDecidesAuthenticationElsewhere(t *testing.T) {
	spring := map[string]string{"src/main/java/app/C.java": springHead + "@RestController\npublic class C {\n  @DeleteMapping(\"/users/{id}\") public void d() {}\n}\n"}
	quarkus := map[string]string{"src/main/java/app/R.java": jaxrsHead + "@Path(\"/users\")\npublic class R {\n  @DELETE @Path(\"/{id}\") public void d() {}\n}\n"}
	cases := []struct {
		name  string
		base  map[string]string
		file  string
		with  string
		other string // same file, nothing that authenticates
	}{
		{"maven starter-security", spring, "pom.xml", "<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>", "<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>"},
		{"gradle kotlin starter-security", spring, "build.gradle.kts", "implementation(\"org.springframework.boot:spring-boot-starter-security\")", "implementation(\"org.springframework.boot:spring-boot-starter-web\")"},
		{"gradle oauth2 resource server", spring, "build.gradle", "implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'", "implementation 'org.springframework.boot:spring-boot-starter-web'"},
		{"quarkus permission", quarkus, "src/main/resources/application.properties", "quarkus.http.auth.permission.all.paths=/*\nquarkus.http.auth.permission.all.policy=authenticated\n", "quarkus.http.port=8081\n"},
		{"quarkus policy enforcer", quarkus, "src/main/resources/application.properties", "quarkus.keycloak.policy-enforcer.enable=true\n", "quarkus.keycloak.policy-enforcer.enable=false\n"},
		{"quarkus yaml policy enforcer", quarkus, "src/main/resources/application.yml", "quarkus:\n  keycloak:\n    policy-enforcer:\n      enable: true\n", "quarkus:\n  keycloak:\n    policy-enforcer:\n      enable: false\n"},
		{"quarkus yaml permission", quarkus, "src/main/resources/application.yml", "quarkus:\n  http:\n    auth:\n      permission:\n        all:\n          paths: /*\n          policy: authenticated\n", "quarkus:\n  http:\n    port: 8081\n"},
	}
	for _, c := range cases {
		t.Run(c.name+" silences", func(t *testing.T) {
			a, _ := scanFiles(t, withFile(c.base, c.file, c.with))
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v (routes %v)", got, routeKeys(a))
			}
			if len(a.Routes()) != 1 {
				t.Fatalf("the route must still be read: %v", routeKeys(a))
			}
		})
		t.Run(c.name+" control leads", func(t *testing.T) {
			a, _ := scanFiles(t, withFile(c.base, c.file, c.other))
			if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
				t.Fatalf("leads = %v", got)
			}
		})
	}
	t.Run("a test resource does not secure the application", func(t *testing.T) {
		a, _ := scanFiles(t, withFile(quarkus, "src/test/resources/application.properties", "quarkus.http.auth.permission.all.paths=/*\n"))
		if got := authnLeads(a); !slices.Equal(got, []string{"DELETE /users/{id}"}) {
			t.Fatalf("leads = %v", got)
		}
	})
}

// Configuration belongs to its module: in a repository of independent
// applications under one aggregator pom (quarkus-quickstarts), one module's
// permission policy says nothing about its siblings. A dependency declared by
// the parent covers its children.
func TestJVMConfigurationIsScopedToItsModule(t *testing.T) {
	res := jaxrsHead + "@Path(\"/users\")\npublic class R {\n  @DELETE @Path(\"/{id}\") public void d() {}\n}\n"
	modules := map[string]string{
		"pom.xml": "<project/>", "a/pom.xml": "<project/>", "b/pom.xml": "<project/>",
		"a/src/main/java/app/R.java": res, "b/src/main/java/app/R.java": res,
	}
	a, _ := scanFiles(t, withFile(modules, "a/src/main/resources/application.properties", "quarkus.http.auth.permission.all.paths=/*\n"))
	var got []string
	for _, l := range a.Leads() {
		got = append(got, l.FilePath)
	}
	if !slices.Equal(got, []string{"b/src/main/java/app/R.java"}) {
		t.Fatalf("leads in %v, want only module b", got)
	}
	a, _ = scanFiles(t, withFile(modules, "pom.xml", "<dependency><artifactId>spring-boot-starter-security</artifactId></dependency>"))
	if got := authnLeads(a); len(got) != 0 {
		t.Fatalf("a dependency of the parent covers both modules, got leads %v", got)
	}
}
