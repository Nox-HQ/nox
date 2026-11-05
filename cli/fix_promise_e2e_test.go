package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm's legacy shasum field, not a security use
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/npmtree"
	"github.com/nox-hq/nox/core/remediate"
)

// The plan keeps its promises. Every npm fix nox offers, wherever it offers it
// (the finding, nox fix plan, nox fix apply), is checked against what real npm
// then does:
//
//   - all three give one answer: a command, or "held" with no command;
//   - a command offered, when run, leaves no copy below the fix and the finding
//     gone on a rescan;
//   - "held" is offered only when npm really cannot move the package.
//
// Unit tests checked each surface against its own idea of npm, and the three
// disagreed about minimatch 10.2.6 in nox's own VS Code extension: `npm install
// minimatch@11.0.1` (a second copy beside the vulnerable one), "a major, check
// the release notes", and an `npm update` that moved nothing. This runs npm
// itself, against a registry served here, so it needs no network and the
// versions never change under it.
func TestNPMFixesKeepTheirPromise(t *testing.T) {
	npm, err := exec.LookPath("npm")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("npm is not installed; CI must run this, not skip it")
		}
		t.Skip("npm is not installed")
	}

	// child 1.0.0 is vulnerable. 1.0.1 and 2.0.0 are published after the
	// project installs, as fixes are.
	parents := map[string]string{
		"parent-caret": "^1.0.0",           // allows a minor fix, not a major one
		"parent-exact": "1.0.0",            // allows neither
		"parent-wide":  "^1.0.0 || ^2.0.0", // allows both
	}
	cases := []struct {
		name     string
		rootDeps map[string]string
		fixed    string
		wantHeld bool
	}{
		{"transitive, minor fix its parent allows", map[string]string{"parent-caret": "1.0.0"}, "1.0.1", false},
		{"transitive, major fix its parent excludes", map[string]string{"parent-caret": "1.0.0"}, "2.0.0", true},
		{"transitive, minor fix an exact pin excludes", map[string]string{"parent-exact": "1.0.0"}, "1.0.1", true},
		{"transitive, major fix its parent allows", map[string]string{"parent-wide": "1.0.0"}, "2.0.0", false},
		{"transitive, one of two parents excludes", map[string]string{"parent-caret": "1.0.0", "parent-exact": "1.0.0"}, "1.0.1", true},
		{"direct, minor fix", map[string]string{"child": "^1.0.0"}, "1.0.1", false},
		{"direct, major fix", map[string]string{"child": "^1.0.0"}, "2.0.0", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := newFakeNPMRegistry(t)
			reg.publish("child", "1.0.0", nil)
			for name, rng := range parents {
				reg.publish(name, "1.0.0", map[string]string{"child": rng})
			}
			osv := fakeAdvisory(t, "child", tc.fixed)
			npmEnv(t, reg.URL())

			// The project as npm itself installs it, before the fixes exist.
			project := t.TempDir()
			manifest, _ := json.Marshal(map[string]any{"name": "app", "version": "1.0.0", "dependencies": tc.rootDeps})
			writeBytes(t, filepath.Join(project, "package.json"), manifest)
			runNPM(t, npm, project, "install", "--ignore-scripts")
			reg.publish("child", "1.0.1", nil)
			reg.publish("child", "2.0.0", nil)

			// 1. The finding.
			finding := childFinding(t, project, osv)
			fCmd := finding.Metadata["remediation_command"]

			// 2. The plan.
			item := onlyPlanItem(t, remediate.Build(remediate.Input{Findings: []findings.Finding{finding}, Root: project}))
			planHeld := item.Kind == remediate.KindHeldUpgrade

			// 3. Apply, on its own copy.
			applied := copyProject(t, project)
			applyErr := applyNpmUpgrade(applied, upgradeAction{pkg: "child", toVersion: tc.fixed, ecosystem: "npm", manifest: "package-lock.json"})

			// One answer.
			if planHeld != tc.wantHeld {
				t.Errorf("plan: held=%v, want %v (%s: %s)", planHeld, tc.wantHeld, item.Kind, item.Why)
			}
			if (fCmd == "") != tc.wantHeld {
				t.Errorf("finding: command %q, want held=%v", fCmd, tc.wantHeld)
			}
			if !tc.wantHeld && item.Command != fCmd {
				t.Errorf("plan offers %q, the finding %q: two answers to one question", item.Command, fCmd)
			}

			if tc.wantHeld {
				// Held means npm cannot move it: apply refuses without running
				// npm, and the refusal names the same holder the plan does.
				if applyErr == nil || !strings.Contains(applyErr.Error(), "requires child") {
					t.Errorf("apply on a held package: %v, want a refusal naming the holder", applyErr)
				}
				if below, _ := npmtree.Below(applied, "child", tc.fixed); len(below) == 0 {
					t.Error("held, yet something moved the package")
				}
				// The apply's own plan list says held too, rather than a
				// command it is about to refuse.
				findingsPath := filepath.Join(t.TempDir(), "findings.json")
				doc, _ := json.Marshal(map[string]any{"findings": []findings.Finding{finding}})
				writeBytes(t, findingsPath, doc)
				var code int
				out := captureStdout(t, func() { code = runDepsFix(findingsPath, copyProject(t, project), true, true) })
				if !strings.Contains(out, "held: child") || strings.Contains(out, "plan: npm") {
					t.Errorf("dry run (exit %d) does not say held:\n%s\nfindings: %s", code, out, doc)
				}
				// And held is true of npm, not only of nox: npm update leaves it.
				probe := copyProject(t, project)
				runNPM(t, npm, probe, "update", "--ignore-scripts", "child")
				if below, _ := npmtree.Below(probe, "child", tc.fixed); len(below) == 0 {
					t.Error("nox called this held, but npm update moved it to the fix")
				}
				return
			}

			// Offered means it works: apply's run and the finding's command,
			// each on its own copy, leave no copy below the fix and no finding.
			if applyErr != nil {
				t.Fatalf("apply: %v", applyErr)
			}
			assertFixed(t, applied, osv, tc.fixed, "apply")
			literal := copyProject(t, project)
			args := strings.Fields(fCmd)
			if len(args) < 2 || args[0] != "npm" {
				t.Fatalf("finding command %q is not an npm command", fCmd)
			}
			runNPM(t, npm, literal, args[1:]...)
			assertFixed(t, literal, osv, tc.fixed, "the finding's command")
		})
	}
}

func assertFixed(t *testing.T, dir string, osv *httptest.Server, fixed, by string) {
	t.Helper()
	if below, err := npmtree.Below(dir, "child", fixed); err != nil || len(below) > 0 {
		t.Errorf("%s left %v below %s (%v)", by, below, fixed, err)
	}
	for _, f := range scanChild(t, dir, osv) {
		if f.RuleID == "VULN-001" {
			t.Errorf("%s: the finding is still there on a rescan: %s", by, f.Message)
		}
	}
}

func childFinding(t *testing.T, dir string, osv *httptest.Server) findings.Finding {
	t.Helper()
	for _, f := range scanChild(t, dir, osv) {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "child" {
			return f
		}
	}
	t.Fatal("the scan reported no VULN-001 for child")
	return findings.Finding{}
}

func scanChild(t *testing.T, dir string, osv *httptest.Server) []findings.Finding {
	t.Helper()
	lock := filepath.Join(dir, "package-lock.json")
	st, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	a := deps.NewAnalyzer(deps.WithOSVBaseURL(osv.URL), deps.WithHTTPClient(osv.Client()))
	_, fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{{
		Path: "package-lock.json", AbsPath: lock, Type: discovery.Lockfile, Size: st.Size(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

func onlyPlanItem(t *testing.T, p remediate.Plan) remediate.Item {
	t.Helper()
	if len(p.Items) != 1 {
		t.Fatalf("plan items = %d, want 1: %+v", len(p.Items), p.Items)
	}
	return p.Items[0]
}

// npmEnv points npm at the fake registry with a private cache, and keeps it
// from reaching anything else.
func npmEnv(t *testing.T, registry string) {
	t.Helper()
	for k, v := range map[string]string{
		"npm_config_registry":        registry,
		"npm_config_cache":           t.TempDir(),
		"npm_config_audit":           "false",
		"npm_config_fund":            "false",
		"npm_config_update_notifier": "false",
		"npm_config_fetch_retries":   "0",
		"npm_config_ignore_scripts":  "true",
		"npm_config_userconfig":      filepath.Join(t.TempDir(), "npmrc"),
	} {
		t.Setenv(k, v)
	}
}

func runNPM(t *testing.T, npm, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(npm, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("npm %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func copyProject(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "app")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return dst
}

func writeBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeNPMRegistry serves packuments and tarballs the way registry.npmjs.org does,
// for the packages a test publishes.
type fakeNPMRegistry struct {
	srv  *httptest.Server
	mu   sync.Mutex
	pkgs map[string]map[string]fakeVersion // name -> version -> published
}

type fakeVersion struct {
	deps    map[string]string
	tarball []byte
}

func newFakeNPMRegistry(t *testing.T) *fakeNPMRegistry {
	t.Helper()
	r := &fakeNPMRegistry{pkgs: map[string]map[string]fakeVersion{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeNPMRegistry) URL() string { return r.srv.URL + "/" }

func (r *fakeNPMRegistry) publish(name, version string, requires map[string]string) {
	manifest, _ := json.Marshal(map[string]any{"name": name, "version": version, "dependencies": requires})
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(manifest)
	_ = tw.Close()
	_ = gz.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pkgs[name] == nil {
		r.pkgs[name] = map[string]fakeVersion{}
	}
	r.pkgs[name][version] = fakeVersion{deps: requires, tarball: buf.Bytes()}
}

func (r *fakeNPMRegistry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := strings.TrimPrefix(req.URL.Path, "/")
	if name, file, ok := strings.Cut(path, "/-/"); ok {
		version := strings.TrimSuffix(strings.TrimPrefix(file, name+"-"), ".tgz")
		v, found := r.pkgs[name][version]
		if !found {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(v.tarball)
		return
	}
	versions, found := r.pkgs[path]
	if !found {
		http.NotFound(w, req)
		return
	}
	doc := map[string]any{"name": path}
	vs := map[string]any{}
	var names []string
	for ver, v := range versions {
		names = append(names, ver)
		sha := sha512.Sum512(v.tarball)
		sha1sum := sha1.Sum(v.tarball) //nolint:gosec // npm's legacy shasum field
		vs[ver] = map[string]any{
			"name": path, "version": ver, "dependencies": v.deps,
			"dist": map[string]any{
				"tarball":   fmt.Sprintf("%s%s/-/%s-%s.tgz", r.URL(), path, path, ver),
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha[:]),
				"shasum":    hex.EncodeToString(sha1sum[:]),
			},
		}
	}
	sort.Strings(names) // the fixtures' versions sort lexically as semver
	doc["versions"] = vs
	doc["dist-tags"] = map[string]string{"latest": names[len(names)-1]}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// fakeAdvisory is an OSV endpoint with one advisory: pkg below fixed.
func fakeAdvisory(t *testing.T, pkg, fixed string) *httptest.Server {
	t.Helper()
	const id = "GHSA-test-fix-promise"
	advisory := fmt.Sprintf(`{"id":%q,"summary":"test advisory","affected":[{"package":{"name":%q,"ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":%q}]}]}]}`, id, pkg, fixed)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			_, _ = w.Write([]byte(advisory))
			return
		}
		var q struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		results := make([]map[string]any, len(q.Queries))
		for i, query := range q.Queries {
			results[i] = map[string]any{}
			if query.Package.Name == pkg && versionLess(query.Version, fixed) {
				results[i]["vulns"] = []map[string]string{{"id": id}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	t.Cleanup(srv.Close)
	return srv
}
