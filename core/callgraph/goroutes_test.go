package callgraph

import (
	"reflect"
	"testing"
)

// A Go route registration names its handler, and the handler becomes an entry
// a request reaches: a function, a method value, a function from another
// package of the module.
func TestGoRouteHandlersAreEntries(t *testing.T) {
	root := module(t, map[string]string{
		"main.go": `package main

import (
	"net/http"

	"example.com/m/api"
)

type H struct{}

func (H) Show(w http.ResponseWriter, r *http.Request) { load() }

func load() {}

func create(w http.ResponseWriter, r *http.Request) { load() }

func main() {
	h := H{}
	http.HandleFunc("/c", create)
	http.HandleFunc("/s", h.Show)
	http.Handle("/l", http.HandlerFunc(api.List))
	http.HandleFunc("/f", func(w http.ResponseWriter, r *http.Request) {})
}
`,
		"api/api.go": `package api

import "net/http"

func List(w http.ResponseWriter, r *http.Request) {}
`,
	})
	g := BuildGo(root)
	g.MarkGoRoutes(root, []Route{
		{Method: "ALL", Path: "/c", File: "main.go", Line: 19, Reader: "net/http"},
		{Method: "ALL", Path: "/s", File: "main.go", Line: 20, Reader: "net/http"},
		{Method: "ALL", Path: "/l", File: "main.go", Line: 21, Reader: "net/http"},
		{Method: "ALL", Path: "/f", File: "main.go", Line: 22, Reader: "net/http"},
	})
	for _, k := range []string{"create", "(H).Show", "api.List"} {
		f, ok := g.Func(k)
		if !ok || f.Kind != EntryRoute {
			t.Errorf("%s: kind = %v, want route", k, f)
		}
	}
	// load is reached from main and from two handlers; the route wins.
	if path, kind := g.PathToFunc("load"); kind != EntryRoute || len(path) != 2 {
		t.Errorf("PathToFunc(load) = %v from %s, want a two-step path from a route", path, kind)
	}
	// main registers routes and is not one.
	if f, _ := g.Func("main"); f.Kind != EntryConcrete {
		t.Errorf("main is %s", f.Kind)
	}
	if got := g.funcRefs; got == nil {
		t.Fatal("no refs collected")
	}
	if !reflect.DeepEqual(g.Scope().Analysis, "go/ast call graph") {
		t.Errorf("Go scope renamed: %q", g.Scope().Analysis)
	}
}
