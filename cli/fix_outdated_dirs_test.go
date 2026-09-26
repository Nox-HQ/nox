package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The directories a currency pass covers come from .nox.yaml, defaulting to
// the root, and none may lie outside it: the list is repository input, and a
// path that climbs out would run a package manager somewhere nobody pointed
// nox at.
func TestOutdatedDirectories(t *testing.T) {
	for _, tc := range []struct {
		in      []string
		want    string
		wantErr bool
	}{
		{nil, ".", false},
		{[]string{".", "editors/vscode"}, ".,editors/vscode", false},
		{[]string{"editors/vscode/", "./editors/vscode"}, "editors/vscode", false},
		{[]string{"../elsewhere"}, "", true},
		{[]string{"/etc"}, "", true},
		{[]string{`\\etc`}, "", true},
	} {
		got, err := outdatedDirectories(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("%v: err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && strings.Join(got, ",") != tc.want {
			t.Errorf("%v: got %v, want %s", tc.in, got, tc.want)
		}
	}
}

// Dependabot covered nox's root and editors/vscode because its config listed
// both. --outdated read manifests at --root only, so the VS Code extension's
// dependencies went unchecked once nox took over. Each configured directory is
// planned in its own right, and nothing outside the list is touched: examples/
// and testdata/ hold fixtures that are old or vulnerable on purpose.
func TestOutdatedPlansEachConfiguredDirectory(t *testing.T) {
	root := t.TempDir()
	project := func(dir, dep string) {
		t.Helper()
		abs := filepath.Join(root, dir)
		if err := os.MkdirAll(abs, 0o755); err != nil {
			t.Fatal(err)
		}
		pkg := `{"dependencies": {"` + dep + `": "^1.0.0"}}`
		lock := `{"lockfileVersion": 3, "packages": {"node_modules/` + dep + `": {"version": "1.0.0"}}}`
		if err := os.WriteFile(filepath.Join(abs, "package.json"), []byte(pkg), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(abs, "package-lock.json"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	project(".", "rootdep")
	project("editors/vscode", "vscodedep")
	project("examples/demo", "demodep")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.1.0"}}`))
	}))
	defer srv.Close()

	plan, degraded := planOutdated(root, []string{".", "editors/vscode"}, false, map[string]string{"npm": srv.URL})
	if len(degraded) != 0 {
		t.Fatalf("degraded: %v", degraded)
	}
	var got []string
	for _, a := range plan.actions {
		dir, err := workdirFor(root, a)
		if err != nil {
			t.Fatalf("%s: %v", a.pkg, err)
		}
		rel, _ := filepath.Rel(root, dir)
		got = append(got, a.pkg+"@"+filepath.ToSlash(rel))
	}
	sort.Strings(got)
	want := "rootdep@.,vscodedep@editors/vscode"
	if strings.Join(got, ",") != want {
		t.Errorf("planned %v, want %s", got, want)
	}
}

// @types/vscode describes the API an extension may call and must track
// engines.vscode, not the newest VS Code: a newer one compiles code against
// APIs older supported editors lack, and vsce refuses to package it. Dependabot
// was told to take patch releases only; fix.outdated.hold says the same, and
// the reason is printed so a held upgrade is never silent.
func TestAHeldPackageMovesOnlyAsFarAsAllowed(t *testing.T) {
	holds := []outdatedHold{{Package: "@types/vscode", Allow: "patch", Reason: "tracks engines.vscode"}}
	actions := []upgradeAction{
		{pkg: "@types/vscode", fromVer: "1.91.0", toVersion: "1.138.0", ecosystem: "npm"},
		{pkg: "@types/vscode", fromVer: "1.91.0", toVersion: "1.91.4", ecosystem: "npm"},
		{pkg: "@types/node", fromVer: "26.6.2", toVersion: "26.7.0", ecosystem: "npm"},
	}
	kept, held := applyHolds(actions, holds)
	var got []string
	for _, a := range kept {
		got = append(got, a.pkg+"@"+a.toVersion)
	}
	if strings.Join(got, ",") != "@types/vscode@1.91.4,@types/node@26.7.0" {
		t.Errorf("kept %v", got)
	}
	if len(held) != 1 || !strings.Contains(held[0], "1.138.0") || !strings.Contains(held[0], "tracks engines.vscode") {
		t.Errorf("held line must name the target and the reason; got %v", held)
	}
}

// A hold with no reason, or an allow level nobody defined, explains nothing
// and is refused rather than silently holding or silently not.
func TestAHoldMustSayWhy(t *testing.T) {
	for _, h := range []outdatedHold{
		{Package: "x", Allow: "patch"},
		{Package: "x", Allow: "sometimes", Reason: "r"},
		{Allow: "patch", Reason: "r"},
	} {
		if err := validateHolds([]outdatedHold{h}); err == nil {
			t.Errorf("%+v was accepted", h)
		}
	}
	if err := validateHolds([]outdatedHold{{Package: "x", Allow: "minor", Reason: "r"}}); err != nil {
		t.Errorf("a complete hold was refused: %v", err)
	}
}
