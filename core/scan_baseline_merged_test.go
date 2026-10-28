package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

// Two records for one vulnerability, as NOX Intelligence v0.20.0 sends them.
// sameAs controls whether it says so; a service before v0.20.0 did not, and a
// baseline written against it holds one entry per record.
func twoIDIntel(t *testing.T, sameAs bool) *httptest.Server {
	t.Helper()
	rec := func(id, other, summary string) string {
		s := ""
		if sameAs {
			s = `,"nox_same_as":["` + other + `"]`
		}
		return `{"id":"` + id + `","modified":"2026-05-01T00:00:00Z","summary":"` + summary + `","aliases":["` + other + `"]` + s + `}`
	}
	unrelated := `{"id":"GHSA-zzzz-zzzz-zzzz","modified":"2026-05-01T00:00:00Z","summary":"a different flaw"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			_, _ = w.Write([]byte(`{"id":"` + id + `"}`)) // a 404 would be a missing detail: advisory_detail
			return
		}
		body := `{"results":[{"vulns":[` + rec("GHSA-aaaa-bbbb-cccc", "GO-2021-9999", "proto pollution") + `,` +
			rec("GO-2021-9999", "GHSA-aaaa-bbbb-cccc", "prototype pollution in x") + `,` + unrelated + `]}]}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func scanTwoID(t *testing.T, dir string, sameAs bool) *ScanResult {
	t.Helper()
	t.Setenv(IntelligenceEndpointEnv, twoIDIntel(t, sameAs).URL)
	ref := osvDown(t)
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"),
		[]byte("scan:\n  osv:\n    base_url: "+ref.URL+"\n    cache_disabled: true\n  intelligence:\n    verification: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{BaselinePath: filepath.Join(dir, "bl.json")})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func vulnByID(res *ScanResult) map[string]findings.Finding {
	out := map[string]findings.Finding{}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "VULN-001" {
			out[f.Metadata["vuln_id"]] = f
		}
	}
	return out
}

func acceptFingerprints(t *testing.T, dir string, fps ...string) {
	t.Helper()
	bl, err := baseline.Load(filepath.Join(dir, "bl.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fp := range fps {
		bl.Add(&baseline.Entry{Fingerprint: fp, RuleID: "VULN-001", FilePath: "package-lock.json"})
	}
	if err := bl.Save(filepath.Join(dir, "bl.json")); err != nil {
		t.Fatal(err)
	}
}

// Upgrading must not turn CI red for an unchanged dependency: an entry written
// when the duplicate was its own finding still accepts the merged one.
func TestBaseline_EntryForAMergedDuplicateStillAcceptsTheSurvivor(t *testing.T) {
	dir := lockfileProject(t, "")
	before := vulnByID(scanTwoID(t, dir, false))
	if len(before) != 3 {
		t.Fatalf("before the merge there are %d findings, want 3", len(before))
	}
	// The operator accepted only the GO- record's finding. After the merge the
	// survivor is the GHSA- one, whose own fingerprint is not in the baseline.
	acceptFingerprints(t, dir, before["GO-2021-9999"].Fingerprint)

	after := vulnByID(scanTwoID(t, dir, true))
	if len(after) != 2 {
		t.Fatalf("after the merge there are %d findings, want 2: %v", len(after), after)
	}
	merged := after["GHSA-aaaa-bbbb-cccc"]
	if merged.Status != findings.StatusBaselined {
		t.Errorf("the merged finding is %q; the entry for its duplicate no longer accepts it", merged.Status)
	}
	if merged.Metadata["baseline_match"] != baseline.ViaAliasFingerprint ||
		merged.Metadata["baseline_entry"] != before["GO-2021-9999"].Fingerprint {
		t.Errorf("the output does not say which entry matched and how: %v", merged.Metadata)
	}
}

// ...and only that one. A different advisory on the same package is still new.
func TestBaseline_MergedEntryDoesNotAcceptADifferentAdvisory(t *testing.T) {
	dir := lockfileProject(t, "")
	before := vulnByID(scanTwoID(t, dir, false))
	acceptFingerprints(t, dir, before["GO-2021-9999"].Fingerprint)
	after := vulnByID(scanTwoID(t, dir, true))
	if got := after["GHSA-zzzz-zzzz-zzzz"].Status; got == findings.StatusBaselined {
		t.Error("an entry for one advisory accepted a different advisory on the same package")
	}
}

// The same id on another version is another finding: the message names the
// version, so its fingerprint differs.
func TestBaseline_MergedEntryDoesNotAcceptAnotherVersion(t *testing.T) {
	dir := lockfileProject(t, "")
	before := vulnByID(scanTwoID(t, dir, false))
	acceptFingerprints(t, dir, before["GO-2021-9999"].Fingerprint)

	other := lockfileProject(t, "")
	lock := `{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`
	if err := os.WriteFile(filepath.Join(other, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "bl.json"), filepath.Join(other, "bl.json")); err != nil {
		t.Fatal(err)
	}
	after := vulnByID(scanTwoID(t, other, true))
	if got := after["GHSA-aaaa-bbbb-cccc"].Status; got == findings.StatusBaselined {
		t.Error("an entry for lodash 4.17.15 accepted the same advisory on 4.17.21")
	}
}

// A baseline that already holds the survivor's own entry matches by
// fingerprint, as before, and records nothing extra.
func TestBaseline_SurvivorOwnEntryMatchesByFingerprint(t *testing.T) {
	dir := lockfileProject(t, "")
	before := vulnByID(scanTwoID(t, dir, false))
	acceptFingerprints(t, dir, before["GHSA-aaaa-bbbb-cccc"].Fingerprint)
	merged := vulnByID(scanTwoID(t, dir, true))["GHSA-aaaa-bbbb-cccc"]
	if merged.Status != findings.StatusBaselined {
		t.Fatalf("status %q", merged.Status)
	}
	if _, ok := merged.Metadata["baseline_match"]; ok {
		t.Errorf("a plain fingerprint match was annotated as an alias match: %v", merged.Metadata)
	}
}
