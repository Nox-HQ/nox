package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestOutcomeTermsVersionPinsTheText(t *testing.T) {
	sum := sha256.Sum256([]byte(OutcomeTerms))
	got := hex.EncodeToString(sum[:])
	const pinned = "b35abf917564571ea3fcf2259e7ea1f4158733ca0c544c9549776a018017a39f"
	if OutcomeTermsVersion == "outcomes-2026-11" && got != pinned {
		t.Fatalf("outcome terms changed but version is still %s (sha256 %s). Bump OutcomeTermsVersion, "+
			"and the service's NOXINTEL_OUTCOME_TERMS, then update this pin.", OutcomeTermsVersion, got)
	}
	if !strings.Contains(OutcomeTerms, "version "+OutcomeTermsVersion) {
		t.Error("the terms text does not name its own version")
	}
}

func TestOutcomeConsentIsSeparateAndVersioned(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "salt")
	if s, _ := LoadOutcomeConsent(sp); s != ConsentNone {
		t.Fatalf("fresh machine: %v", s)
	}
	if err := RecordConsent(sp, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadOutcomeConsent(sp); s != ConsentNone {
		t.Fatal("accepting the contribution terms accepted the outcome terms too")
	}
	if err := RecordOutcomeConsent(sp, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadOutcomeConsent(sp); s != ConsentGranted {
		t.Fatalf("after accept: %v", s)
	}
	if err := WithdrawOutcomeConsent(sp); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadOutcomeConsent(sp); s != ConsentNone {
		t.Fatalf("after withdraw: %v", s)
	}
	if s, _ := LoadConsent(sp); s != ConsentGranted {
		t.Fatal("withdrawing outcome consent withdrew contribution consent")
	}
}

func TestProjectPseudonym(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a", "salt"), filepath.Join(dir, "b", "salt")
	const root = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	p1, err := ProjectPseudonym(a, root)
	if err != nil {
		t.Fatal(err)
	}
	if p2, _ := ProjectPseudonym(a, root); p2 != p1 {
		t.Error("the pseudonym is not stable for one repository on one installation")
	}
	if p3, _ := ProjectPseudonym(b, root); p3 == p1 {
		t.Error("two installations gave one repository the same pseudonym: it is joinable across them")
	}
	if p4, _ := ProjectPseudonym(a, "0000000000000000000000000000000000000000"); p4 == p1 {
		t.Error("two repositories share a pseudonym")
	}
	if strings.Contains(p1, root) || len(p1) != 64 {
		t.Errorf("pseudonym %q is not a 64-hex HMAC", p1)
	}
	id, _ := ReporterID(a)
	key, _ := DeletionKey(a)
	if p1 == id || p1 == key {
		t.Error("the pseudonym equals another identity derived from the salt")
	}
	if _, err := ProjectPseudonym(a, " "); err == nil {
		t.Error("an empty root commit gave a pseudonym")
	}
}

func TestOutcomeAllowlistMatchesTheStructs(t *testing.T) {
	var want []string
	for _, f := range OutcomeAllowlist() {
		want = append(want, f.Name)
	}
	var got []string
	for _, n := range jsonNames(reflect.TypeOf(OutcomeReport{})) {
		if n != "findings" {
			got = append(got, n)
		}
	}
	for _, n := range jsonNames(reflect.TypeOf(OutcomeFinding{})) {
		got = append(got, "findings[]."+n)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist and wire fields differ:\n wire      %v\n allowlist %v", got, want)
	}
}

func jsonNames(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		out = append(out, strings.Split(t.Field(i).Tag.Get("json"), ",")[0])
	}
	return out
}

func vuln(meta map[string]string) findings.Finding {
	return findings.Finding{RuleID: "VULN-001", Metadata: meta}
}

func TestDeriveOutcomeFindings(t *testing.T) {
	goVuln := map[string]string{
		"ecosystem": "go", "package": "golang.org/x/net", "version": "v0.6.0", "vuln_id": "GO-2023-1571",
		"applicability": "undetermined", "applicability_reached": "affected_version",
		"applicability_stopped_at": "call_reachable", "applicability_because": "not_evaluated",
		"dependency_imported": "true",
		// Things that must never leave, present on the real finding.
		"affected_symbol_site": "cmd/server/main.go:42", "priority_why": "HIGH severity",
	}
	npmVuln := map[string]string{"ecosystem": "npm", "package": "lodash", "version": "4.17.20",
		"vuln_id": "GHSA-35jh-r3h4-6jhm", "applicability": "not_impacting", "dependency_imported": "false"}
	bad := map[string]string{"ecosystem": "npm", "package": "x", "version": "1.0.0", "vuln_id": "GHSA-a",
		"applicability": "undetermined", "applicability_because": "see cmd/x.go"}
	fs := []findings.Finding{
		vuln(npmVuln), vuln(goVuln), vuln(goVuln), // a duplicate
		vuln(bad),                                  // a reason that is prose: left out, counted
		{RuleID: "SEC-001", Metadata: goVuln},      // not a dependency finding
		vuln(map[string]string{"ecosystem": "go"}), // incomplete
	}
	out, skipped := DeriveOutcomeFindings(fs)
	want := []OutcomeFinding{
		{Ecosystem: "go", Package: "golang.org/x/net", Version: "v0.6.0", Advisory: "GO-2023-1571",
			Applicability: "undetermined", Reached: "affected_version", StoppedAt: "call_reachable",
			Because: "not_evaluated", Imported: "yes"},
		{Ecosystem: "npm", Package: "lodash", Version: "4.17.20", Advisory: "GHSA-35jh-r3h4-6jhm",
			Applicability: "not_impacting", Imported: "no"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("derived:\n got %+v\nwant %+v", out, want)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (the prose reason and the incomplete record)", skipped)
	}
	b, _ := json.Marshal(out)
	for _, leak := range []string{"main.go", "HIGH", "cmd/"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("derived findings carry %q: %s", leak, b)
		}
	}
}

func TestDeriveOutcomeFindingsIsBounded(t *testing.T) {
	var fs []findings.Finding
	for i := 0; i < maxOutcomeFindings+7; i++ {
		fs = append(fs, vuln(map[string]string{"ecosystem": "npm", "package": fmt.Sprintf("p%d", i),
			"version": "1.0.0", "vuln_id": "GHSA-abc", "applicability": "undetermined"}))
	}
	out, skipped := DeriveOutcomeFindings(fs)
	if len(out) != maxOutcomeFindings || skipped != 7 {
		t.Fatalf("%d kept, %d skipped; want %d kept and the 7 over the bound counted", len(out), skipped, maxOutcomeFindings)
	}
}

func TestSubmitOutcomeIsAnonymousAndPostsTheReport(t *testing.T) {
	var gotAuth, gotPath string
	var got OutcomeReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"findings":0}`))
	}))
	defer srv.Close()
	r := OutcomeReport{SchemaVersion: 1, ConsentVersion: TermsVersion, OutcomeTerms: OutcomeTermsVersion,
		ReporterID: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), ObservedAt: "2026-11-03T00:00:00Z"}
	// Even a client holding an organisation token sends outcomes anonymously.
	if _, err := NewClient(srv.URL, nil).WithToken("org-token").SubmitOutcome(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("outcome report sent a credential (%q): the pseudonym is now joinable to the organisation", gotAuth)
	}
	if gotPath != "/v1/outcomes" || got.Project != r.Project || got.Findings == nil {
		t.Errorf("posted %s %+v", gotPath, got)
	}

	r.OutcomeTerms = ""
	if _, err := NewClient(srv.URL, nil).SubmitOutcome(context.Background(), r); err == nil {
		t.Error("a report without outcome terms was sent")
	}
}

func TestSubmitOutcomeReportsTheRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"outcome_terms \"x\" is not accepted","code":"outcome_terms_unrecognised"}`))
	}))
	defer srv.Close()
	r := OutcomeReport{SchemaVersion: 1, ConsentVersion: TermsVersion, OutcomeTerms: OutcomeTermsVersion,
		ReporterID: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), ObservedAt: "x"}
	_, err := NewClient(srv.URL, nil).SubmitOutcome(context.Background(), r)
	if err == nil || !strings.Contains(err.Error(), "outcome_terms_unrecognised") {
		t.Fatalf("err = %v", err)
	}
}

// The derivation is pinned to a vector computed outside Go (Python's hmac):
// a release that changed it would give every project a new pseudonym and
// silently cut each one's history in two.
func TestProjectPseudonymDerivationIsPinned(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "salt")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	if err := os.WriteFile(sp, salt, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ProjectPseudonym(sp, "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
	if err != nil {
		t.Fatal(err)
	}
	const want = "9cf19ee2a268ee4c1198a24c40ea8cacb6fc41e2da82d8b4aacbd024458d065d"
	if got != want {
		t.Fatalf("pseudonym = %s, want %s: the derivation changed, and every project's history with it", got, want)
	}
}
