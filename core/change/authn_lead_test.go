package change

import (
	"os"
	"path/filepath"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// The vision's first example: a change that adds an unauthenticated route must
// show up in the delta between two scans, not only in `nox model`. This runs
// the two scans through the real engine.
func TestANewUnauthenticatedRouteIsInTheDelta(t *testing.T) {
	const head = "const express = require('express');\nconst app = express();\nconst db = require('./db');\n" +
		"app.get('/api/me', requireAuth, (req, res) => res.json(req.user));\n"
	const del = "app.delete('/api/users/:id', async (req, res) => { await db.query('delete from users where id=$1', [req.params.id]); res.end(); });\n"

	scan := func(src string) State {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "src", "server.js"), []byte(src+"app.listen(3000);\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, DisableOSV: true})
		if err != nil {
			t.Fatal(err)
		}
		return FromScan(res, "t")
	}
	prev, cur := scan(head), scan(head+del)
	d := Compare(prev, cur)
	if len(d.NewLeads) != 1 || d.NewLeads[0].Route != "DELETE /api/users/:id" || d.NewLeads[0].Category != "authentication" {
		t.Fatalf("new leads = %+v, want one authentication lead for DELETE /api/users/:id", d.NewLeads)
	}
	if got := Compare(cur, prev); len(got.ResolvedLeads) != 1 {
		t.Errorf("removing the route should resolve the lead: %+v", got.ResolvedLeads)
	}
	if same := Compare(cur, cur); len(same.NewLeads) != 0 {
		t.Errorf("an unchanged route is new: %+v", same.NewLeads)
	}
}
