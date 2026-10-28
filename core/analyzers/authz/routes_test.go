package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func routesOf(t *testing.T, files map[string]string) []Route {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arts, err := discovery.NewWalker(dir).Walk()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer()
	if _, err := a.ScanArtifacts(context.Background(), arts); err != nil {
		t.Fatal(err)
	}
	if len(a.Routes()) != a.RoutesRead() {
		t.Fatalf("Routes() has %d entries but RoutesRead() is %d", len(a.Routes()), a.RoutesRead())
	}
	return a.Routes()
}

// Every route is inventoried, not only the ones that meet AUTHZ-001's
// proposition, and each carries the middleware visibly in front of it.
func TestRoutesInventoryEveryRegistrationWithItsVisibleMiddleware(t *testing.T) {
	rs := routesOf(t, map[string]string{
		"src/server.js": "const express = require('express');\nconst app = express();\n" +
			"app.post('/login', login);\n" +
			"app.use('/api/items', require('./items'));\n",
		"src/items.js": "const express = require('express');\nconst router = express.Router();\n" +
			"router.use(requireAuth);\n" +
			"router.get('/', list);\n" +
			"router.delete('/:id', requireRole('admin'), remove);\n" +
			"module.exports = router;\n",
	})
	want := map[string]Route{
		"POST /login":           {Method: "POST", Path: "/login", FilePath: "src/server.js", Line: 3},
		"GET /api/items":        {Method: "GET", Path: "/api/items", FilePath: "src/items.js", Line: 4, Authn: "requireAuth"},
		"DELETE /api/items/:id": {Method: "DELETE", Path: "/api/items/:id", FilePath: "src/items.js", Line: 5, Authn: "requireAuth"},
	}
	if len(rs) != len(want) {
		t.Fatalf("got %d routes, want %d: %+v", len(rs), len(want), rs)
	}
	for _, r := range rs {
		w, ok := want[r.Method+" "+r.Path]
		if !ok {
			t.Errorf("unexpected route %s %s", r.Method, r.Path)
			continue
		}
		if r.FilePath != w.FilePath || r.Line != w.Line || r.Authn != w.Authn {
			t.Errorf("%s %s = %+v, want file %s line %d authn %q", r.Method, r.Path, r, w.FilePath, w.Line, w.Authn)
		}
	}
	for _, r := range rs {
		if r.Method == "DELETE" && r.Authz == "" {
			t.Errorf("DELETE route should carry the requireRole middleware as Authz, got %+v", r)
		}
	}
}

// A scan with no Express routes inventories none: the absence is "not read",
// and the consumer is told so by the key being absent.
func TestRoutesEmptyWhenNothingIsExpress(t *testing.T) {
	if rs := routesOf(t, map[string]string{"main.go": "package main\nfunc main() {}\n"}); len(rs) != 0 {
		t.Fatalf("got routes for a Go program: %+v", rs)
	}
}
