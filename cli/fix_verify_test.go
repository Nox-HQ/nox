package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeGoMod(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Planning correctly is not landing correctly. `go get` resolves against the
// whole module graph, so a constraint elsewhere can put a package below the
// requested version — and the result is a "chore(security)" diff that lowers a
// dependency, which is precisely the diff a reviewer does not scrutinise.
func TestVerifyNoRegression(t *testing.T) {
	tests := []struct {
		name        string
		goMod       string
		action      upgradeAction
		wantBad     bool
		wantUnknown bool
	}{
		{
			name:   "landed where asked",
			goMod:  "module m\n\nrequire golang.org/x/crypto v0.54.0\n",
			action: upgradeAction{pkg: "golang.org/x/crypto", fromVer: "0.51.0", toVersion: "0.54.0", ecosystem: "go"},
		},
		{
			name:   "landed above the target is fine — it still clears the advisory",
			goMod:  "module m\n\nrequire golang.org/x/crypto v0.55.0\n",
			action: upgradeAction{pkg: "golang.org/x/crypto", fromVer: "0.51.0", toVersion: "0.54.0", ecosystem: "go"},
		},
		{
			// The failure this exists for: the manager resolved lower than
			// where we started.
			name:    "landed below where it started",
			goMod:   "module m\n\nrequire golang.org/x/crypto v0.51.0\n",
			action:  upgradeAction{pkg: "golang.org/x/crypto", fromVer: "0.54.0", toVersion: "0.56.0", ecosystem: "go"},
			wantBad: true,
		},
		{
			// Unchanged is not a regression — the upgrade simply did not take,
			// which the apply step already reports.
			name:   "unchanged is not a regression",
			goMod:  "module m\n\nrequire golang.org/x/crypto v0.54.0\n",
			action: upgradeAction{pkg: "golang.org/x/crypto", fromVer: "0.54.0", toVersion: "0.56.0", ecosystem: "go"},
		},
		{
			name:   "require block form is parsed",
			goMod:  "module m\n\nrequire (\n\tgolang.org/x/crypto v0.54.0\n\tgolang.org/x/text v0.40.0\n)\n",
			action: upgradeAction{pkg: "golang.org/x/text", fromVer: "0.39.0", toVersion: "0.40.0", ecosystem: "go"},
		},
		{
			// Must be reported as unverified, never folded in with the clean
			// results — unchecked is not the same as verified.
			name:        "an ecosystem nox cannot read is unverified, not clean",
			goMod:       "module m\n",
			action:      upgradeAction{pkg: "express", fromVer: "4.18.0", toVersion: "4.19.0", ecosystem: "npm"},
			wantUnknown: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeGoMod(t, dir, tc.goMod)

			bad, unchecked := verifyNoRegression(dir, []upgradeAction{tc.action})

			if got := len(bad) > 0; got != tc.wantBad {
				t.Errorf("regressions=%v, want %v (%+v)", got, tc.wantBad, bad)
			}
			if got := len(unchecked) > 0; got != tc.wantUnknown {
				t.Errorf("unchecked=%v, want %v (%v)", got, tc.wantUnknown, unchecked)
			}
		})
	}
}

// The specular shape end to end: a plan that somehow lowered x/crypto must be
// caught after the fact, not reported as a successful security fix.
func TestVerifyCatchesTheSpecularRegression(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "module m\n\nrequire golang.org/x/crypto v0.51.0\n")

	bad, _ := verifyNoRegression(dir, []upgradeAction{
		{pkg: "golang.org/x/crypto", fromVer: "0.54.0", toVersion: "0.51.0", ecosystem: "go"},
	})
	if len(bad) != 1 {
		t.Fatalf("expected the downgrade to be caught, got %+v", bad)
	}
	if bad[0].from != "0.54.0" || bad[0].actual != "0.51.0" {
		t.Errorf("report = %+v, want from 0.54.0 actual 0.51.0", bad[0])
	}
}
