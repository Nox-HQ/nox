package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// osvDouble answers OSV's querybatch and vulns endpoints from a fixed table and
// records every (name@version) it was asked about. It listens on loopback, so
// the hermetic harness lets it through; nothing leaves the machine.
type osvDouble struct {
	mu      sync.Mutex
	queried []string
	srv     *httptest.Server
}

func newOSVDouble(t *testing.T, advisories map[string]string) *osvDouble {
	t.Helper()
	d := &osvDouble{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
					Version string                           `json:"version"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			type vuln struct {
				ID string `json:"id"`
			}
			results := make([]map[string][]vuln, len(req.Queries))
			d.mu.Lock()
			for i, q := range req.Queries {
				d.queried = append(d.queried, q.Package.Name+"@"+q.Version)
				results[i] = map[string][]vuln{"vulns": {}}
				if id, ok := advisories[q.Package.Name+"@"+q.Version]; ok {
					results[i]["vulns"] = []vuln{{ID: id}}
				}
			}
			d.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "summary": "test advisory " + id,
				"database_specific": map[string]string{"severity": "HIGH"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *osvDouble) asked() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]string(nil), d.queried...)
	sort.Strings(out)
	return out
}

func writeNPMProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func osvConfig(url string) string {
	return "scan:\n  intelligence:\n    disabled: true\n  osv:\n    base_url: " + url + "\n    cache_disabled: true\n"
}

const noLockfileManifest = `{"dependencies":{"axios":"0.21.1","express":"4.17.1"}}`

// The reproduction from the bug report: a package.json and nothing else used to
// scan as "0 dependencies". The declared exact versions are now looked up and the
// known-vulnerable axios 0.21.1 is reported.
func TestScan_NPMManifestWithoutLockfileFindsVulnerabilities(t *testing.T) {
	osv := newOSVDouble(t, map[string]string{"axios@0.21.1": "GHSA-test-axios"})
	dir := writeNPMProject(t, map[string]string{
		"package.json": noLockfileManifest,
		".nox.yaml":    osvConfig(osv.srv.URL),
	})
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Inventory.Packages()); n != 2 {
		t.Errorf("inventory = %d packages, want 2", n)
	}
	if got := strings.Join(osv.asked(), ","); got != "axios@0.21.1,express@4.17.1" {
		t.Errorf("OSV was asked about %q", got)
	}
	var hit bool
	for _, f := range res.Findings.ActiveFindings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "axios" && f.Metadata["version"] == "0.21.1" {
			hit = f.Location.FilePath == "package.json" && f.Metadata["declared_spec"] == ""
		}
	}
	if !hit {
		t.Errorf("no VULN-001 for axios@0.21.1 located at package.json; findings: %v", res.Findings.ActiveFindings())
	}
}

// Offline-first: the dependencies are still listed, with no lookup.
func TestScan_NPMManifestWithoutLockfileOfflineStillListsDependencies(t *testing.T) {
	osv := newOSVDouble(t, nil)
	dir := writeNPMProject(t, map[string]string{
		"package.json": noLockfileManifest,
		".nox.yaml":    osvConfig(osv.srv.URL),
	})
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Inventory.Packages()); n != 2 {
		t.Errorf("offline inventory = %d packages, want 2", n)
	}
	if got := osv.asked(); len(got) != 0 {
		t.Errorf("an offline scan queried OSV: %v", got)
	}
}

// A lockfile beside the manifest is authoritative and nothing is counted twice:
// OSV is asked about the lockfile's version only.
func TestScan_NPMManifestAndLockfileDoNotDoubleCount(t *testing.T) {
	osv := newOSVDouble(t, nil)
	dir := writeNPMProject(t, map[string]string{
		"package.json": `{"dependencies":{"axios":"^0.21.0","express":"4.17.1"}}`,
		"package-lock.json": `{"packages":{"":{"name":"app"},"node_modules/axios":{"version":"0.21.4"},` +
			`"node_modules/express":{"version":"4.17.1"}}}`,
		".nox.yaml": osvConfig(osv.srv.URL),
	})
	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Inventory.Packages()); n != 2 {
		t.Errorf("inventory = %d packages, want 2: %+v", n, res.Inventory.Packages())
	}
	if got := strings.Join(osv.asked(), ","); got != "axios@0.21.4,express@4.17.1" {
		t.Errorf("OSV was asked about %q, want only the lockfile's versions", got)
	}
}
