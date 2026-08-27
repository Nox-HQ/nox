package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The allowlist and the struct must agree. A field added to one and not the
// other either ships without ever being declared shareable, or is declared
// shareable and silently never sent — and a reviewer reading the printed
// allowlist would be misled in both directions.
func TestAllowlistMatchesTheStruct(t *testing.T) {
	declared := make(map[string]struct{})
	for _, f := range Allowlist() {
		declared[f.Name] = struct{}{}
	}

	rt := reflect.TypeOf(Observation{})
	actual := make(map[string]struct{}, rt.NumField())
	for i := range rt.NumField() {
		tag := rt.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			t.Fatalf("Observation.%s has no json name; it cannot be reviewed "+
				"as part of the allowlist", rt.Field(i).Name)
		}
		actual[name] = struct{}{}
		if _, ok := declared[name]; !ok {
			t.Errorf("Observation carries %q but Allowlist does not declare it; "+
				"a field nobody deliberately permitted would be transmitted", name)
		}
	}
	for name := range declared {
		if _, ok := actual[name]; !ok {
			t.Errorf("Allowlist declares %q but Observation has no such field; "+
				"the printed allowlist overstates what is sent", name)
		}
	}
}

// The fingerprint must follow the rule the service recomputes on ingest, or
// every observation is rejected. Agreement with the live service is verified
// end to end; this covers the properties the rule has to have.
func TestFingerprint_NormalisesAndDistinguishes(t *testing.T) {
	got := Fingerprint("npm", "lodash", "<4.17.22", "CWE-1321", "VULN-001")
	if len(got) != 64 {
		t.Fatalf("fingerprint %q is not a sha256 hex digest", got)
	}
	// Normalisation: case and spacing must not split a cluster.
	if a, b := got, Fingerprint("NPM", " lodash ", "<4.17.22", "cwe-1321", "vuln-001"); a != b {
		t.Errorf("normalisation failed: %s != %s", a, b)
	}
	if Fingerprint("npm", "express", "<4.17.22", "CWE-1321", "VULN-001") == got {
		t.Error("different packages produced the same fingerprint")
	}
}

func depFinding(pkg, eco, version, fixed string) findings.Finding {
	return findings.Finding{
		RuleID: "VULN-001",
		Location: findings.Location{
			// A real path, to prove none of it survives derivation.
			FilePath: "apps/web/package-lock.json", StartLine: 1,
		},
		Message: "Known vulnerability in " + pkg,
		Metadata: map[string]string{
			"ecosystem": eco, "package": pkg, "version": version,
			"fixed_in": fixed, "vuln_id": "GHSA-secret-looking",
			"remediation_command": "npm install " + pkg + "@" + fixed,
		},
	}
}

var derOpts = DeriveOptions{
	ReporterID: "reporter-abc", ObservedAt: "2026-08-01T00:00:00Z", ToolVersion: "1.30.0",
}

// Only dependency findings are eligible. Every other rule reports on the
// operator's own code, and the existence of such a finding is a fact about
// their codebase rather than about a package the ecosystem shares.
func TestDerive_OnlyDependencyFindingsAreEligible(t *testing.T) {
	in := []findings.Finding{
		depFinding("lodash", "npm", "4.17.15", "4.17.21"),
		{RuleID: "SEC-001", Location: findings.Location{FilePath: "internal/auth/token.go"},
			Message: "Hardcoded credential", Metadata: map[string]string{"secret": "AKIA..."}},
		{RuleID: "AI-004", Location: findings.Location{FilePath: "agent/prompt.py"},
			Message: "Prompt logged", Metadata: map[string]string{"prompt": "you are..."}},
		{RuleID: "TAINT-002", Location: findings.Location{FilePath: "cmd/api/handler.go"},
			Metadata: map[string]string{"sink": "db.Exec"}},
	}

	got := Derive(in, derOpts)
	if len(got) != 1 {
		t.Fatalf("derived %d observations, want 1 — only VULN-001 may leave", len(got))
	}
	if got[0].Package != "lodash" {
		t.Errorf("package = %q", got[0].Package)
	}
}

// Nothing that identifies the environment may survive derivation. This is the
// property the whole package exists for, so it is asserted over the serialized
// bytes rather than field by field.
func TestDerive_TransmitsNothingIdentifying(t *testing.T) {
	got := Derive([]findings.Finding{
		depFinding("lodash", "npm", "4.17.15", "4.17.21"),
	}, derOpts)

	body, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	wire := string(body)

	for _, forbidden := range []string{
		"apps/web", "package-lock.json", "/", // paths
		"AKIA", "secret", // credential-shaped values
		"npm install",         // command lines
		"Known vulnerability", // free text from the finding
	} {
		if strings.Contains(wire, forbidden) {
			t.Errorf("observation contains %q; the wire form is: %s", forbidden, wire)
		}
	}

	// And positively: what it does carry is only what the allowlist declares.
	var round map[string]any
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatal(err)
	}
	declared := make(map[string]struct{})
	for _, f := range Allowlist() {
		declared[f.Name] = struct{}{}
	}
	for k := range round {
		if _, ok := declared[k]; !ok {
			t.Errorf("wire form carries undeclared field %q", k)
		}
	}
}

// A monorepo that vendors one package in twelve places is still one sighting.
func TestDerive_CollapsesRepeatsWithinOneScan(t *testing.T) {
	in := make([]findings.Finding, 0, 12)
	for range 12 {
		in = append(in, depFinding("lodash", "npm", "4.17.15", "4.17.21"))
	}
	if got := Derive(in, derOpts); len(got) != 1 {
		t.Errorf("derived %d observations from 12 sightings of one issue, want 1", len(got))
	}
}

// Without a known fix there is no truthful upper bound, and inventing one would
// fabricate a security fact.
func TestDerive_NoFixMeansNoRange(t *testing.T) {
	got := Derive([]findings.Finding{
		depFinding("lodash", "npm", "4.17.15", ""),
	}, derOpts)
	if got[0].VersionRange != "" {
		t.Errorf("VersionRange = %q, want empty when no fix is known", got[0].VersionRange)
	}
}

// The id must be stable across calls — an id that changed per scan would make
// one noisy installation look like many corroborating ones.
func TestReporterID_StableAndOpaque(t *testing.T) {
	path := filepath.Join(t.TempDir(), "salt")

	first, err := ReporterID(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReporterID(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("id changed between calls: %s vs %s", first, second)
	}

	other, err := ReporterID(filepath.Join(t.TempDir(), "salt"))
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Error("two installations derived the same reporter id")
	}

	salt, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(first), salt) || strings.Contains(first, string(salt)) {
		t.Error("the reporter id exposes the salt")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not model Unix permission bits: Go's FileMode there drives
	// only the read-only attribute, so a file written 0600 still reports 0666
	// and no mode check can express the property. Confidentiality of the salt
	// on Windows rests on the ACL of the user profile directory holding it,
	// which is not something os.Stat reports. Asserting anyway would either
	// fail honest builds or, if relaxed to a mask, quietly weaken the check on
	// the platforms where it does mean something.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("salt permissions are %v, want 0600 — anything else on the "+
				"machine could impersonate this reporter", perm)
		}
	}
}

// A failed contribution must never fail the scan.
func TestContribute_FailuresAreReportedNotPropagated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid observation: weakness contains \"/\"",
		})
	}))
	defer srv.Close()

	res := NewClient(srv.URL, srv.Client()).Contribute(context.Background(),
		Derive([]findings.Finding{depFinding("lodash", "npm", "4.17.15", "4.17.21")}, derOpts))

	if res.Submitted != 1 || res.Rejected != 1 || res.Accepted != 0 {
		t.Errorf("result = %+v", res)
	}
	if res.FirstError == nil || !strings.Contains(res.FirstError.Error(), "weakness") {
		t.Errorf("the rejection reason was not surfaced: %v", res.FirstError)
	}
}

func TestContribute_AcceptedObservations(t *testing.T) {
	var got Observation
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	res := NewClient(srv.URL, srv.Client()).Contribute(context.Background(),
		Derive([]findings.Finding{depFinding("lodash", "npm", "4.17.15", "4.17.21")}, derOpts))

	if res.Accepted != 1 || res.FirstError != nil {
		t.Fatalf("result = %+v", res)
	}
	if got.Fingerprint != Fingerprint("npm", "lodash", "<4.17.21", "", "VULN-001") {
		t.Errorf("fingerprint does not follow from the facts sent: %+v", got)
	}
	if got.ReporterID != "reporter-abc" {
		t.Errorf("ReporterID = %q", got.ReporterID)
	}
}

func TestPrintAllowlist_ListsEveryFieldAndTheExclusions(t *testing.T) {
	var b bytes.Buffer
	if err := PrintAllowlist(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, f := range Allowlist() {
		if !strings.Contains(out, f.Name) {
			t.Errorf("printed allowlist omits %q", f.Name)
		}
	}
	for _, s := range NeverShared() {
		if !strings.Contains(out, s) {
			t.Errorf("printed allowlist omits the exclusion %q", s)
		}
	}
}
