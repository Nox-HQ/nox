package authz

import (
	"slices"
	"testing"
)

// A debug mux served only on a loopback address is not reachable by anyone
// who is not already on the machine, so its routes are not a missing-
// authentication lead. The same mux on a wildcard or unspecified address is.
func TestGoLoopbackListenerIsNotALead(t *testing.T) {
	const pprofMux = `mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	`
	both := []string{"ALL /debug/pprof/", "ALL /debug/pprof/profile"}
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"http.Server literal on localhost", pprofMux + `server := &http.Server{Addr: "localhost:6060", Handler: mux}
	server.ListenAndServe()`, nil},
		{"ListenAndServe on 127.0.0.1", pprofMux + `http.ListenAndServe("127.0.0.1:6060", mux)`, nil},
		{"ListenAndServe on ipv6 loopback", pprofMux + `http.ListenAndServe("[::1]:6060", mux)`, nil},
		{"multi-line server literal on loopback", pprofMux + `srv := &http.Server{
		Addr:              "127.0.0.1:6060",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv.ListenAndServe()`, nil},
		{"wildcard port only", pprofMux + `http.ListenAndServe(":6060", mux)`, both},
		{"all interfaces", pprofMux + `http.ListenAndServe("0.0.0.0:6060", mux)`, both},
		{"server literal on all interfaces", pprofMux + `server := &http.Server{Addr: ":6060", Handler: mux}
	server.ListenAndServe()`, both},
		{"address from configuration is not assumed loopback", pprofMux + `http.ListenAndServe(cfg.DebugAddr, mux)`, both},
		{"loopback in one server, public in another, is public", pprofMux + `go http.ListenAndServe("localhost:6060", mux)
	http.ListenAndServe(":8080", mux)`, both},
		{"never served", pprofMux, both},
		{"a loopback server for a different mux does not cover this one", pprofMux + `other := http.NewServeMux()
	http.ListenAndServe("localhost:9000", other)`, both},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := scanFiles(t, goMain("package main\n\nimport (\n\t\"net/http\"\n\t\"net/http/pprof\"\n)\n\n", c.body))
			if got := authnLeads(a); !slices.Equal(got, c.want) {
				t.Fatalf("leads = %v, want %v", got, c.want)
			}
			if got := routeKeys(a); len(got) != 2 {
				t.Fatalf("the routes stay in the table; got %v", got)
			}
		})
	}
}
