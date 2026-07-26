package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Currency needs two things per ecosystem that vulnerability scanning does not:
//
//  1. Which dependencies are DIRECT. deps.Package comes from lockfiles, which
//     are flat and include the whole transitive closure. Upgrading a transitive
//     package writes an explicit requirement for something the project does not
//     import — churn the operator has to unpick. Directness lives in the
//     manifest, not the lockfile.
//  2. What the latest published version is, which only a registry can answer.
//
// These tests cover both, per ecosystem, against stub registries.

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestDirectDeps_NPM(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "package.json", `{
	  "name": "app",
	  "dependencies":    { "express": "^4.18.0", "@scope/thing": "1.2.3" },
	  "devDependencies": { "jest": "~29.0.0" }
	}`)
	// The lockfile carries the resolved versions AND the transitive closure.
	writeManifest(t, dir, "package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "node_modules/express":      { "version": "4.18.2" },
	    "node_modules/@scope/thing": { "version": "1.2.3" },
	    "node_modules/jest":         { "version": "29.0.1" },
	    "node_modules/body-parser":  { "version": "1.20.0" }
	  }
	}`)

	got := directDeps(dir)
	byName := map[string]string{}
	for _, d := range got {
		if d.eco == "npm" {
			byName[d.name] = d.version
		}
	}

	for name, want := range map[string]string{
		"express":      "4.18.2",
		"@scope/thing": "1.2.3",
		"jest":         "29.0.1", // devDependencies count: they run in CI
	} {
		if byName[name] != want {
			t.Errorf("npm %s = %q, want %q (resolved version must come from the lockfile, not the range)", name, byName[name], want)
		}
	}
	// The whole point: a transitive package must not appear.
	if v, ok := byName["body-parser"]; ok {
		t.Errorf("body-parser is transitive but was reported as direct (version %q)", v)
	}
}

func TestDirectDeps_Cargo(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "Cargo.toml", `
[package]
name = "app"

[dependencies]
serde = "1.0.100"
tokio = { version = "1.20", features = ["full"] }

[dev-dependencies]
proptest = "1.0"
`)
	writeManifest(t, dir, "Cargo.lock", `
[[package]]
name = "serde"
version = "1.0.150"

[[package]]
name = "tokio"
version = "1.28.0"

[[package]]
name = "proptest"
version = "1.2.0"

[[package]]
name = "libc"
version = "0.2.140"
`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "cargo" {
			byName[d.name] = d.version
		}
	}
	// `tokio` is declared in table form; parsing only bare strings would miss it.
	for name, want := range map[string]string{"serde": "1.0.150", "tokio": "1.28.0", "proptest": "1.2.0"} {
		if byName[name] != want {
			t.Errorf("cargo %s = %q, want %q", name, byName[name], want)
		}
	}
	if _, ok := byName["libc"]; ok {
		t.Error("libc is transitive but was reported as direct")
	}
}

func TestDirectDeps_PyPI(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "requirements.txt", `
# comment
requests==2.28.1
flask>=2.0,<3.0
urllib3 == 1.26.12   # inline comment
-e .
`)

	byName := map[string]string{}
	for _, d := range directDeps(dir) {
		if d.eco == "pypi" {
			byName[d.name] = d.version
		}
	}
	if byName["requests"] != "2.28.1" {
		t.Errorf("requests = %q, want 2.28.1", byName["requests"])
	}
	if byName["urllib3"] != "1.26.12" {
		t.Errorf("urllib3 = %q, want 1.26.12 (whitespace around == must not defeat parsing)", byName["urllib3"])
	}
	// A range pin has no single current version; reporting one would invent a
	// fact. It is listed with an empty version and skipped by the planner.
	if v := byName["flask"]; v != "" {
		t.Errorf("flask = %q, want empty — a range gives no exact current version", v)
	}
	if _, ok := byName["-e ."]; ok {
		t.Error("an editable install was parsed as a package name")
	}
}

// Each registry answers "what is latest" in its own shape. A wrong field means
// silently proposing the wrong upgrade, so each is pinned by a test.
func TestRegistryResolvers(t *testing.T) {
	cases := []struct {
		eco, path, body, want string
	}{
		{"npm", "/express", `{"dist-tags":{"latest":"4.19.2","next":"5.0.0-beta"}}`, "4.19.2"},
		{"pypi", "/pypi/requests/json", `{"info":{"version":"2.31.0"}}`, "2.31.0"},
		{"cargo", "/api/v1/crates/serde", `{"crate":{"max_stable_version":"1.0.197","max_version":"1.1.0-alpha"}}`, "1.0.197"},
	}
	for _, tc := range cases {
		t.Run(tc.eco, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got, err := resolveLatest(tc.eco, pkgNameForPath(tc.path, tc.eco), srv.URL)
			if err != nil {
				t.Fatalf("resolveLatest: %v", err)
			}
			if got != tc.want {
				t.Errorf("latest = %q, want %q", got, tc.want)
			}
		})
	}
}

// Prerelease channels must never win. npm's `next`, cargo's `max_version` and
// PyPI's yanked-but-present releases are all traps: an operator running a
// currency pass wants the current stable, not a beta.
func TestRegistryResolvers_IgnorePrereleaseChannels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"1.0.197","max_version":"2.0.0-rc.1"}}`))
	}))
	defer srv.Close()

	got, err := resolveLatest("cargo", "serde", srv.URL)
	if err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if got != "1.0.197" {
		t.Errorf("cargo latest = %q — max_version is a prerelease and must not be chosen", got)
	}
}

// A registry that is down, rate-limiting, or does not know the package must
// produce an error rather than an empty string that reads as "no update".
func TestRegistryResolvers_ErrorsRatherThanReportingCurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if got, err := resolveLatest("npm", "express", srv.URL); err == nil {
		t.Errorf("a 429 produced no error (returned %q); the package would look up to date", got)
	}
}

// npm's full packument for a popular package is enormous — typescript and
// @types/node both exceed 8 MB — which truncated the response body and surfaced
// as "unexpected end of JSON input" against the real registry. Every dependency
// in the VS Code extension reported as un-checkable.
//
// The fix is to ask for the abbreviated document rather than to keep raising a
// size ceiling, so this asserts the header is actually sent. Found only by
// running against the live registry; no stub was ever big enough to catch it.
func TestNpmResolver_RequestsTheAbbreviatedPackument(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"}}`))
	}))
	defer srv.Close()

	if _, err := resolveLatest("npm", "typescript", srv.URL); err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if gotAccept != "application/vnd.npm.install-v1+json" {
		t.Errorf("Accept = %q, want the abbreviated-packument media type; "+
			"the full document is large enough to truncate", gotAccept)
	}
}
