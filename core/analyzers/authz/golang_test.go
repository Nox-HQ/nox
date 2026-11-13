package authz

import (
	"slices"
	"testing"
)

const (
	ginHead  = "package main\n\nimport (\n\t\"github.com/gin-gonic/gin\"\n)\n\n"
	echoHead = "package main\n\nimport (\n\t\"github.com/labstack/echo/v4\"\n\t\"github.com/labstack/echo/v4/middleware\"\n)\n\n"
	chiHead  = "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/go-chi/chi/v5\"\n)\n\n"
	httpHead = "package main\n\nimport \"net/http\"\n\n"
)

func goMain(head, body string) map[string]string {
	return map[string]string{"cmd/server/main.go": head + "func main() {\n" + body + "\n}\n"}
}

func TestGoRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"gin verbs and nested groups", goMain(ginHead, `r := gin.Default()
	r.GET("/ping", h)
	api := r.Group("/api")
	v1 := api.Group("/v1")
	v1.POST("/users", h)
	v1.PUT("/users/:id", h)
	v1.Any("/any", h)
	r.Handle("PATCH", "/patched", h)`),
			[]string{"ALL /api/v1/any", "GET /ping", "PATCH /patched", "POST /api/v1/users", "PUT /api/v1/users/:id"}},
		{"echo group", goMain(echoHead, `e := echo.New()
	g := e.Group("/admin")
	g.DELETE("/users/:id", h)
	e.GET("/health", h)
	e.Add("POST", "/x", h)`),
			[]string{"DELETE /admin/users/:id", "GET /health", "POST /x"}},
		{"chi route, group, mount and method", goMain(chiHead, `r := chi.NewRouter()
	r.Get("/", h)
	r.Route("/users", func(r chi.Router) {
		r.Get("/{id}", h)
		r.Route("/{id}/keys", func(r chi.Router) {
			r.Delete("/{kid}", h)
		})
	})
	r.Group(func(r chi.Router) {
		r.Put("/profile", h)
	})
	sub := chi.NewRouter()
	sub.Post("/a", h)
	r.Mount("/sub", sub)
	r.Method("PATCH", "/m", h)
	r.Handle("/h", h)`),
			[]string{"ALL /h", "DELETE /users/{id}/keys/{kid}", "GET /", "GET /users/{id}", "PATCH /m", "POST /sub/a", "PUT /profile"}},
		{"net/http patterns", goMain(httpHead, `mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", h)
	mux.Handle("DELETE /users/{id}", h)
	mux.HandleFunc("/plain", h)
	mux.HandleFunc("example.com/host", h)
	http.HandleFunc("/default", h)`),
			[]string{"ALL /default", "ALL /plain", "DELETE /users/{id}", "GET /users/{id}"}},
		{"router handed to a function of the package", map[string]string{
			"cmd/server/main.go":     ginHead + "func main() {\n\tr := gin.Default()\n\tRegister(r.Group(\"/users\"))\n}\n",
			"cmd/server/register.go": ginHead + "func Register(rg *gin.RouterGroup) {\n\trg.DELETE(\"/:id\", h)\n\trg.GET(\"\", h)\n}\n"},
			[]string{"DELETE /users/:id", "GET /users"}},
		{"router handed to a function of another package", map[string]string{
			"main.go":        ginHead + "import \"example.com/app/users\"\nfunc main() {\n\tr := gin.Default()\n\tv1 := r.Group(\"/v1\")\n\tusers.Register(v1.Group(\"/users\"))\n}\n",
			"users/users.go": "package users\nimport \"github.com/gin-gonic/gin\"\nfunc Register(rg *gin.RouterGroup) {\n\trg.DELETE(\"/:id\", h)\n}\n"},
			[]string{"DELETE /v1/users/:id"}},
		{"function that builds and returns a chi router, mounted", map[string]string{
			"main.go": chiHead + "func main() {\n\tr := chi.NewRouter()\n\tr.Mount(\"/admin\", adminRouter())\n}\nfunc adminRouter() chi.Router {\n\tr := chi.NewRouter()\n\tr.Delete(\"/users/{id}\", h)\n\treturn r\n}\n"},
			[]string{"DELETE /admin/users/{id}"}},
		{"path held in a constant is not guessed", goMain(ginHead, "r := gin.Default()\n\tr.GET(pathUsers, h)\n\tr.GET(\"/\"+\"x\", h)"), nil},
		{"a method named GET on something that is not a router", goMain(ginHead, "cache.GET(\"/a\", h)\n\tclient.Get(\"/b\", h)"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderGo {
					t.Errorf("%s %s read by %q", r.Method, r.Path, r.Reader)
				}
			}
		})
	}
}

func TestGoMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"gin delete", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/users/:id\", h)"), []string{"DELETE /users/:id"}},
		{"gin nested group prefixes the path", goMain(ginHead, "r := gin.Default()\n\tapi := r.Group(\"/api\")\n\tv1 := api.Group(\"/v1\")\n\tv1.GET(\"/admin/stats\", h)"), []string{"GET /api/v1/admin/stats"}},
		{"gin: Use after the route does not cover it", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/users/:id\", h)\n\tr.Use(AuthMiddleware())\n\tr.PUT(\"/users/:id\", h)"), []string{"DELETE /users/:id"}},
		{"gin: a group's Use does not cover its sibling or parent", goMain(ginHead, "r := gin.Default()\n\tsafe := r.Group(\"/safe\")\n\tsafe.Use(AuthMiddleware())\n\topen := r.Group(\"/open\")\n\tsafe.DELETE(\"/a/:id\", h)\n\topen.DELETE(\"/b/:id\", h)\n\tr.DELETE(\"/c/:id\", h)"), []string{"DELETE /c/:id", "DELETE /open/b/:id"}},
		{"gin: a group made before the Use does not get it", goMain(ginHead, "r := gin.Default()\n\tg := r.Group(\"/g\")\n\tr.Use(AuthMiddleware())\n\tg.DELETE(\"/x/:id\", h)"), []string{"DELETE /g/x/:id"}},
		{"gin: logging, recovery and rate limits are not authentication", goMain(ginHead, "r := gin.New()\n\tr.Use(gin.Logger(), gin.Recovery(), RateLimit(), cors.Default())\n\tr.DELETE(\"/users/:id\", Throttle(), h)"), []string{"DELETE /users/:id"}},
		{"gin: a handler named for auth is not middleware", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/widgets/:id\", auth.Revoke)"), []string{"DELETE /widgets/:id"}},
		{"gin: a middleware constructed with false lets anonymous callers through", goMain(ginHead, "r := gin.Default()\n\tr.Use(AuthMiddleware(false))\n\tr.DELETE(\"/users/:id\", h)"), []string{"DELETE /users/:id"}},
		{"chi: jwtauth.Verifier only decodes the token", goMain(chiHead, "r := chi.NewRouter()\n\tr.Use(jwtauth.Verifier(tokenAuth))\n\tr.Delete(\"/users/{id}\", h)"), []string{"DELETE /users/{id}"}},
		{"echo delete and group", goMain(echoHead, "e := echo.New()\n\tg := e.Group(\"/api\")\n\tg.DELETE(\"/users/:id\", h)"), []string{"DELETE /api/users/:id"}},
		{"echo: group Use after the route does not cover it", goMain(echoHead, "e := echo.New()\n\tg := e.Group(\"/api\")\n\tg.DELETE(\"/users/:id\", h)\n\tg.Use(middleware.JWT(key))"), []string{"DELETE /api/users/:id"}},
		{"echo: middleware.Logger is not authentication", goMain(echoHead, "e := echo.New()\n\te.Use(middleware.Logger(), middleware.CORS())\n\te.DELETE(\"/users/:id\", h)"), []string{"DELETE /users/:id"}},
		{"chi delete", goMain(chiHead, "r := chi.NewRouter()\n\tr.Delete(\"/users/{id}\", h)"), []string{"DELETE /users/{id}"}},
		{"chi: With on one route does not cover the next", goMain(chiHead, "r := chi.NewRouter()\n\tr.With(requireAuth).Get(\"/a\", h)\n\tr.Delete(\"/users/{id}\", h)"), []string{"DELETE /users/{id}"}},
		{"chi: Use inside one Route does not cover another", goMain(chiHead, "r := chi.NewRouter()\n\tr.Route(\"/safe\", func(r chi.Router) {\n\t\tr.Use(requireAuth)\n\t\tr.Delete(\"/{id}\", h)\n\t})\n\tr.Route(\"/open\", func(r chi.Router) {\n\t\tr.Delete(\"/{id}\", h)\n\t})"), []string{"DELETE /open/{id}"}},
		{"chi: mounted sub-router", map[string]string{"main.go": chiHead + "func main() {\n\tr := chi.NewRouter()\n\tr.Mount(\"/admin\", adminRouter())\n}\nfunc adminRouter() chi.Router {\n\tr := chi.NewRouter()\n\tr.Get(\"/users\", h)\n\treturn r\n}\n"}, []string{"GET /admin/users"}},
		{"net/http delete", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)"), []string{"DELETE /users/{id}"}},
		{"net/http default mux", goMain(httpHead, "http.HandleFunc(\"/admin/export\", h)"), []string{"ALL /admin/export"}},
		{"net/http: wrapping a different mux does not cover this one", goMain(httpHead, "a := http.NewServeMux()\n\tb := http.NewServeMux()\n\ta.HandleFunc(\"DELETE /a/{id}\", h)\n\tb.HandleFunc(\"DELETE /b/{id}\", h)\n\thttp.ListenAndServe(\":80\", requireAuth(a))"), []string{"DELETE /b/{id}"}},
		{"net/http: a logging wrapper is not authentication", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", logRequests(h))\n\thttp.ListenAndServe(\":80\", logging(mux))"), []string{"DELETE /users/{id}"}},
		{"net/http: auth.Setup(mux) is registration, not a wrapper", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)\n\terr := auth.Setup(mux)\n\thttp.ListenAndServe(\":80\", mux)"), []string{"DELETE /users/{id}"}},
		{"a router in a struct field with no Use anywhere", map[string]string{"server.go": ginHead + "type Server struct {\n\trouter *gin.Engine\n}\nfunc (s *Server) routes() {\n\ts.router.DELETE(\"/users/:id\", h)\n}\n"}, []string{"DELETE /users/:id"}},
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

func TestGoSafeVariantsAreNotLeads(t *testing.T) {
	del := "r.DELETE(\"/users/:id\", h)"
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"gin: engine Use before", goMain(ginHead, "r := gin.Default()\n\tr.Use(AuthMiddleware())\n\t"+del)},
		{"gin: group Use", goMain(ginHead, "r := gin.Default()\n\tg := r.Group(\"/api\")\n\tg.Use(JWTAuth())\n\tg.DELETE(\"/users/:id\", h)")},
		{"gin: group created with middleware", goMain(ginHead, "r := gin.Default()\n\tg := r.Group(\"/api\", AuthRequired())\n\tg.DELETE(\"/users/:id\", h)")},
		{"gin: nested group inherits", goMain(ginHead, "r := gin.Default()\n\tr.Use(AuthMiddleware())\n\tg := r.Group(\"/api\")\n\tv := g.Group(\"/v1\")\n\tv.DELETE(\"/users/:id\", h)")},
		{"gin: route middleware", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/users/:id\", AuthMiddleware(), h)")},
		{"gin: BasicAuth", goMain(ginHead, "r := gin.Default()\n\tg := r.Group(\"/admin\", gin.BasicAuth(gin.Accounts{}))\n\tg.GET(\"/stats\", h)")},
		{"gin: authorization middleware only", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/users/:id\", RequireRole(\"admin\"), h)")},
		{"gin: inline middleware checks", goMain(ginHead, "r := gin.Default()\n\tr.Use(func(c *gin.Context) {\n\t\tif c.GetHeader(\"Authorization\") == \"\" {\n\t\t\tc.AbortWithStatus(http.StatusUnauthorized)\n\t\t}\n\t})\n\t"+del)},
		{"gin: handler literal checks", goMain(ginHead, "r := gin.Default()\n\tr.DELETE(\"/users/:id\", func(c *gin.Context) {\n\t\tif c.GetHeader(\"Authorization\") == \"\" {\n\t\t\tc.Status(http.StatusUnauthorized)\n\t\t\treturn\n\t\t}\n\t})")},
		{"gin: named handler checks", map[string]string{"main.go": ginHead + "func main() {\n\tr := gin.Default()\n\tr.DELETE(\"/users/:id\", removeUser)\n}\nfunc removeUser(c *gin.Context) {\n\tif c.GetHeader(\"Authorization\") == \"\" {\n\t\tc.AbortWithStatus(401)\n\t}\n}\n"}},
		{"gin: router passed down, Use in caller", map[string]string{"main.go": ginHead + "func main() {\n\tr := gin.Default()\n\tg := r.Group(\"/v1\")\n\tg.Use(AuthMiddleware())\n\tRegister(g)\n}\nfunc Register(rg *gin.RouterGroup) {\n\trg.DELETE(\"/:id\", h)\n}\n"}},
		{"gin: a middleware constructed with true", goMain(ginHead, "r := gin.Default()\n\tr.Use(AuthMiddleware(true))\n\t"+del)},
		{"echo: echo-jwt", map[string]string{"main.go": "package main\nimport (\n\t\"github.com/labstack/echo/v4\"\n\techojwt \"github.com/labstack/echo-jwt/v4\"\n)\nfunc main() {\n\te := echo.New()\n\te.Use(echojwt.WithConfig(cfg))\n\te.DELETE(\"/users/:id\", h)\n}\n"}},
		{"echo: Use before", goMain(echoHead, "e := echo.New()\n\te.Use(middleware.JWT(key))\n\te.DELETE(\"/users/:id\", h)")},
		{"echo: Use after covers the engine", goMain(echoHead, "e := echo.New()\n\te.DELETE(\"/users/:id\", h)\n\te.Use(middleware.JWT(key))")},
		{"echo: group Use before", goMain(echoHead, "e := echo.New()\n\tg := e.Group(\"/api\")\n\tg.Use(middleware.KeyAuth(f))\n\tg.DELETE(\"/users/:id\", h)")},
		{"echo: group with middleware", goMain(echoHead, "e := echo.New()\n\tg := e.Group(\"/api\", middleware.BasicAuth(f))\n\tg.DELETE(\"/users/:id\", h)")},
		{"echo: route middleware after handler", goMain(echoHead, "e := echo.New()\n\te.DELETE(\"/users/:id\", h, middleware.JWT(key))")},
		{"chi: Use", goMain(chiHead, "r := chi.NewRouter()\n\tr.Use(requireAuth)\n\tr.Delete(\"/users/{id}\", h)")},
		{"chi: jwtauth.Authenticator", goMain(chiHead, "r := chi.NewRouter()\n\tr.Use(jwtauth.Verifier(tokenAuth))\n\tr.Use(jwtauth.Authenticator)\n\tr.Delete(\"/users/{id}\", h)")},
		{"chi: With", goMain(chiHead, "r := chi.NewRouter()\n\tr.With(requireAuth).Delete(\"/users/{id}\", h)")},
		{"chi: Group closure", goMain(chiHead, "r := chi.NewRouter()\n\tr.Group(func(r chi.Router) {\n\t\tr.Use(requireAuth)\n\t\tr.Delete(\"/users/{id}\", h)\n\t})")},
		{"chi: Route inherits parent Use", goMain(chiHead, "r := chi.NewRouter()\n\tr.Use(requireAuth)\n\tr.Route(\"/users\", func(r chi.Router) {\n\t\tr.Delete(\"/{id}\", h)\n\t})")},
		{"chi: Mount sub-router under Use", goMain(chiHead, "r := chi.NewRouter()\n\tr.Use(requireAuth)\n\tsub := chi.NewRouter()\n\tsub.Delete(\"/{id}\", h)\n\tr.Mount(\"/users\", sub)")},
		{"net/http: wrapped handler", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.Handle(\"DELETE /users/{id}\", requireAuth(h))")},
		{"net/http: nested wrappers", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.Handle(\"DELETE /users/{id}\", logging(requireAuth(http.HandlerFunc(h))))")},
		{"net/http: server wrapped", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)\n\thttp.ListenAndServe(\":80\", requireAuth(mux))")},
		{"net/http: Handler field wrapped", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)\n\tsrv := &http.Server{\n\t\tAddr: \":80\",\n\t\tHandler: authMiddleware(mux),\n\t}\n\tsrv.ListenAndServe()")},
		{"net/http: Handler assigned wrapped", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)\n\tsrv := &http.Server{}\n\tsrv.Handler = authMiddleware(mux)")},
		{"net/http: wrapped into a variable", goMain(httpHead, "mux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", h)\n\thandler := authMiddleware(mux)\n\thttp.ListenAndServe(\":80\", handler)")},
		{"net/http: default mux wrapped", goMain(httpHead, "http.HandleFunc(\"/admin/export\", h)\n\thttp.ListenAndServe(\":80\", requireAuth(http.DefaultServeMux))")},
		{"net/http: handler checks the caller", map[string]string{"main.go": httpHead + "func main() {\n\tmux := http.NewServeMux()\n\tmux.HandleFunc(\"DELETE /users/{id}\", remove)\n}\nfunc remove(w http.ResponseWriter, r *http.Request) {\n\tif r.Header.Get(\"Authorization\") == \"\" {\n\t\thttp.Error(w, \"no\", http.StatusUnauthorized)\n\t}\n}\n"}},
		{"an unbound router parameter is unseen", map[string]string{"routes.go": ginHead + "func Register(rg *gin.RouterGroup) {\n\trg.DELETE(\"/users/:id\", h)\n}\n"}},
		{"a struct-field router with Use elsewhere is unseen", map[string]string{"server.go": ginHead + "type Server struct {\n\trouter *gin.Engine\n}\nfunc (s *Server) middleware() {\n\ts.router.Use(AuthMiddleware())\n}\nfunc (s *Server) routes() {\n\ts.router.DELETE(\"/users/:id\", h)\n}\n"}},
		{"test files are not read", map[string]string{"cmd/main_test.go": ginHead + "func TestX() {\n\tr := gin.Default()\n\tr.DELETE(\"/users/:id\", h)\n}\n"}},
		{"example directories are not production", map[string]string{"examples/basic/main.go": ginHead + "func main() {\n\tr := gin.Default()\n\tr.DELETE(\"/users/:id\", h)\n}\n"}},
	}
	for _, c := range cases {
		name, files := c.name, c.files
		t.Run(name, func(t *testing.T) {
			a, _ := scanFiles(t, files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			// A case that proves nothing when the route was never read.
			if len(a.Routes()) == 0 && name != "test files are not read" {
				t.Fatalf("no route was read, so the case guards nothing")
			}
		})
	}
}

// A route the guard does cover still appears in the route table, with the
// middleware that was attributed to it.
func TestGoRoutesNameTheirAuthentication(t *testing.T) {
	a, _ := scanFiles(t, goMain(ginHead, "r := gin.Default()\n\tr.GET(\"/open\", h)\n\tg := r.Group(\"/api\")\n\tg.Use(AuthMiddleware())\n\tg.DELETE(\"/users/:id\", h)"))
	got := map[string]string{}
	for _, r := range a.Routes() {
		got[r.Method+" "+r.Path] = r.Authn
	}
	want := map[string]string{"GET /open": "", "DELETE /api/users/:id": "AuthMiddleware()"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: Authn = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}
