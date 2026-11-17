package authz

import (
	"slices"
	"testing"
)

const muxHead = "package main\n\nimport (\n\t\"net/http\"\n\n\t\"github.com/gorilla/mux\"\n)\n\n"

func muxMain(body string) map[string]string { return goMain(muxHead, body) }

func TestGorillaMuxRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"HandleFunc with Methods", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/health\", h).Methods(\"GET\")\n\tr.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")"),
			[]string{"DELETE /users/{id}", "GET /health"}},
		{"several methods make several routes", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/orders\", h).Methods(\"POST\", \"put\")"),
			[]string{"POST /orders", "PUT /orders"}},
		{"no Methods answers every method", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/any\", h)\n\tr.Handle(\"/hnd\", handler)"),
			[]string{"ALL /any", "ALL /hnd"}},
		{"regexp variable is kept", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/users/{id:[0-9]+}\", h).Methods(\"GET\")"),
			[]string{"GET /users/{id:[0-9]+}"}},
		{"subrouter by PathPrefix", muxMain("r := mux.NewRouter()\n\tapi := r.PathPrefix(\"/api/v1\").Subrouter()\n\tapi.HandleFunc(\"/orders\", h).Methods(\"POST\")\n\tinner := api.PathPrefix(\"/admin\").Subrouter()\n\tinner.HandleFunc(\"/stats\", h).Methods(\"GET\")"),
			[]string{"GET /api/v1/admin/stats", "POST /api/v1/orders"}},
		{"Path builder with HandlerFunc", muxMain("r := mux.NewRouter()\n\tr.Path(\"/a\").Methods(\"PATCH\").HandlerFunc(h)\n\tr.Methods(\"GET\").Path(\"/b\").Handler(hh)\n\tr.Path(\"/c\").HandlerFunc(h)"),
			[]string{"ALL /c", "GET /b", "PATCH /a"}},
		{"router handed to a function", map[string]string{
			"main.go":   muxHead + "func main() {\n\tr := mux.NewRouter()\n\tregister(r.PathPrefix(\"/u\").Subrouter())\n}\n",
			"routes.go": muxHead + "func register(s *mux.Router) {\n\ts.HandleFunc(\"/{id}\", h).Methods(\"DELETE\")\n}\n"},
			[]string{"DELETE /u/{id}"}},
		{"HandleFunc on something that is not a mux router", map[string]string{"main.go": muxHead + "func main() {\n\tcache.HandleFunc(\"/a\", h).Methods(\"GET\")\n\tr := other.NewRouter()\n\tr.HandleFunc(\"/b\", h).Methods(\"GET\")\n}\n"}, nil},
		{"path held in a constant is not guessed", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(pathUsers, h).Methods(\"GET\")"), nil},
		{"methods held in a variable are not guessed", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/x\", h).Methods(verb)"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := routeKeys(a); !slices.Equal(got, c.want) {
				t.Fatalf("routes = %v, want %v", got, c.want)
			}
			for _, r := range a.Routes() {
				if r.Reader != ReaderGorillaMux {
					t.Errorf("%s %s read by %q, want %q", r.Method, r.Path, r.Reader, ReaderGorillaMux)
				}
			}
		})
	}
}

// A file that imports gorilla/mux under another name and keeps a net/http
// ServeMux in a variable named mux: the std router is still the Go reader's.
func TestGorillaMuxDoesNotClaimTheStdServeMux(t *testing.T) {
	a, _ := scanFiles(t, map[string]string{"main.go": "package main\nimport (\n\t\"net/http\"\n\tgmux \"github.com/gorilla/mux\"\n)\nvar _ = gmux.Vars\nfunc main() {\n\tmux := http.NewServeMux()\n\tmux.HandleFunc(\"GET /std\", h)\n}\n"})
	rs := a.Routes()
	if len(rs) != 1 || rs[0].Reader != ReaderGo || rs[0].Path != "/std" {
		t.Fatalf("routes = %+v, want one /std route read by the Go reader", rs)
	}
}

func TestGorillaMuxMissingAuthenticationLeads(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"delete with nothing in front", muxMain("r := mux.NewRouter()\n\tr.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")"), []string{"DELETE /users/{id}"}},
		{"admin route in a subrouter", muxMain("r := mux.NewRouter()\n\ta := r.PathPrefix(\"/admin\").Subrouter()\n\ta.HandleFunc(\"/stats\", h).Methods(\"GET\")"), []string{"GET /admin/stats"}},
		{"a subrouter's Use does not cover its sibling or parent", muxMain("r := mux.NewRouter()\n\tsafe := r.PathPrefix(\"/safe\").Subrouter()\n\tsafe.Use(authMiddleware)\n\topen := r.PathPrefix(\"/open\").Subrouter()\n\tsafe.HandleFunc(\"/a/{id}\", h).Methods(\"DELETE\")\n\topen.HandleFunc(\"/b/{id}\", h).Methods(\"DELETE\")\n\tr.HandleFunc(\"/c/{id}\", h).Methods(\"DELETE\")"), []string{"DELETE /c/{id}", "DELETE /open/b/{id}"}},
		{"logging middleware is not authentication", muxMain("r := mux.NewRouter()\n\tr.Use(loggingMiddleware, mux.CORSMethodMiddleware(r))\n\tr.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")"), []string{"DELETE /users/{id}"}},
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

func TestGorillaMuxSafeVariantsAreNotLeads(t *testing.T) {
	del := "r.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")"
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"Use before", muxMain("r := mux.NewRouter()\n\tr.Use(authMiddleware)\n\t" + del)},
		{"Use after the route covers it too: mux applies middleware when a request matches", muxMain("r := mux.NewRouter()\n\t" + del + "\n\tr.Use(authMiddleware)")},
		{"Use through MiddlewareFunc", muxMain("r := mux.NewRouter()\n\tr.Use(mux.MiddlewareFunc(requireAuth))\n\t" + del)},
		{"parent Use covers a subrouter", muxMain("r := mux.NewRouter()\n\tr.Use(jwtMiddleware)\n\ts := r.PathPrefix(\"/api\").Subrouter()\n\ts.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")")},
		{"subrouter Use", muxMain("r := mux.NewRouter()\n\ts := r.PathPrefix(\"/api\").Subrouter()\n\ts.Use(authMiddleware)\n\ts.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")")},
		{"wrapped handler", muxMain("r := mux.NewRouter()\n\tr.Handle(\"/users/{id}\", requireAuth(http.HandlerFunc(h))).Methods(\"DELETE\")")},
		{"server wrapped", muxMain("r := mux.NewRouter()\n\t" + del + "\n\thttp.ListenAndServe(\":80\", requireAuth(r))")},
		{"handler checks the caller", map[string]string{"main.go": muxHead + "func main() {\n\tr := mux.NewRouter()\n\tr.HandleFunc(\"/users/{id}\", remove).Methods(\"DELETE\")\n}\nfunc remove(w http.ResponseWriter, r *http.Request) {\n\tif r.Header.Get(\"Authorization\") == \"\" {\n\t\thttp.Error(w, \"no\", http.StatusUnauthorized)\n\t}\n}\n"}},
		{"an unbound router parameter is unseen", map[string]string{"routes.go": muxHead + "func register(s *mux.Router) {\n\ts.HandleFunc(\"/users/{id}\", h).Methods(\"DELETE\")\n}\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, c.files)
			if got := authnLeads(a); len(got) != 0 {
				t.Fatalf("leads = %v, want none (routes %v)", got, routeKeys(a))
			}
			if len(a.Routes()) == 0 {
				t.Fatal("no route was read, so the case guards nothing")
			}
		})
	}
}
