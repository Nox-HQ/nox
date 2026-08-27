package deps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// stubSource is a vulnsource.Source that answers from a fixture, so a test can
// assert what the analyzer does with records without standing up an OSV server.
type stubSource struct {
	name    string
	records map[string][]vulnsource.Record
	err     error
	queries []vulnsource.Query
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) Lookup(_ context.Context, qs []vulnsource.Query) (map[int][]vulnsource.Record, error) {
	s.queries = qs
	if s.err != nil {
		return nil, s.err
	}
	out := make(map[int][]vulnsource.Record)
	for i, q := range qs {
		if recs, ok := s.records[q.Name]; ok {
			out[i] = recs
		}
	}
	return out, nil
}

// npmLockfile writes a minimal package-lock.json naming one dependency.
func npmLockfile(t *testing.T, name, version string) (string, []discovery.Artifact) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	body := `{"name":"app","lockfileVersion":3,"packages":{"node_modules/` + name +
		`":{"version":"` + version + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}
	return dir, []discovery.Artifact{{Path: path, AbsPath: path, Type: discovery.Lockfile}}
}

// A source supplied through WithSource is the one that gets asked, and the
// endpoint configured for the default OSV source is not consulted. Without
// this, "swappable" would rest on the absence of a compile error.
func TestWithSource_ReplacesTheDefaultSource(t *testing.T) {
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"lodash": {{
				ID:       "STUB-0001",
				Summary:  "Prototype pollution",
				Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
				Aliases:  []string{"CVE-2020-28500"},
			}},
		},
	}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	a := NewAnalyzer(
		WithSource(src),
		// An endpoint that would fail loudly if the default source were built.
		WithOSVBaseURL("http://127.0.0.1:1"),
	)

	_, fs, err := a.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	if len(src.queries) != 1 {
		t.Fatalf("expected the stub source to be queried once, got %d queries", len(src.queries))
	}
	if got := src.queries[0]; got.Name != "lodash" || got.Ecosystem != "npm" {
		t.Errorf("query = %+v, want lodash/npm", got)
	}

	var found *findings.Finding
	all := fs.Findings()
	for i, f := range all {
		if f.RuleID == "VULN-001" {
			found = &all[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no VULN-001 finding from the stub source's record")
	}
	if found.Metadata["vuln_id"] != "STUB-0001" {
		t.Errorf("vuln_id = %q, want STUB-0001", found.Metadata["vuln_id"])
	}
}

// Records from any source pass through the same severity mapping as an OSV
// record. A source must not be able to acquire different treatment by being a
// different source — the seam carries data, not policy.
func TestWithSource_RecordsGetTheSameSeverityTreatment(t *testing.T) {
	// A CVSS v4 vector with nothing else: scorable only via the coarse label,
	// which is exactly the case database_specific.severity exists to cover.
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"lodash": {{
				ID:      "STUB-V4",
				Summary: "v4-only advisory",
				Severity: []vulnsource.Severity{{
					Type:  "CVSS_V4",
					Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				}},
				DatabaseSpecific: vulnsource.DatabaseSpecific{Severity: "CRITICAL"},
			}},
		},
	}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	for _, f := range fs.Findings() {
		if f.RuleID != "VULN-001" {
			continue
		}
		if f.Severity != findings.SeverityCritical {
			t.Errorf("severity = %v, want critical from the database_specific label", f.Severity)
		}
		return
	}
	t.Fatal("no VULN-001 finding")
}

// A source that cannot answer at all fails the scan rather than returning a
// clean result. Degradation covers "I reached it and it went wrong"; an error
// means the lookup could not be attempted, and swallowing that would report an
// unexercised check as an all-clear.
func TestWithSource_LookupErrorFailsTheScan(t *testing.T) {
	src := &stubSource{name: "stub", err: errors.New("boom")}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, _, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err == nil {
		t.Fatal("expected an error when the source cannot be queried")
	}
	if !errors.Is(err, src.err) {
		t.Errorf("error = %v, want it to wrap the source error", err)
	}
	// The source is named, so an operator can tell which one failed.
	if got := err.Error(); !strings.Contains(got, "stub") {
		t.Errorf("error %q does not name the failing source", got)
	}
}

// Without WithSource the analyzer builds an OSV source, and it reads OSVBaseURL
// at scan time rather than at construction — the field is exported and callers
// set it directly.
func TestDefaultSource_IsOSVAndReadsBaseURLLate(t *testing.T) {
	a := NewAnalyzer()
	if got := a.vulnSource().Name(); got != "osv.dev" {
		t.Errorf("default source = %q, want osv.dev", got)
	}

	deg := &degrade.Degradations{}
	a = NewAnalyzer(WithDegradations(deg))
	a.OSVBaseURL = "http://127.0.0.1:1" // set after construction

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, _, err := a.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts should degrade, not error: %v", err)
	}
	if deg.Len() == 0 {
		t.Fatal("an unreachable endpoint must be recorded as a degradation, " +
			"or an empty result reads as a clean scan")
	}
}

// A published advisory keeps its severity and gates. Nothing about adding a
// status axis may change how the existing, overwhelmingly common case behaves.
func TestStatus_PublishedRecordGatesUnchanged(t *testing.T) {
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"lodash": {{
			ID:       "GHSA-published",
			Summary:  "Prototype pollution",
			Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
			// No Intelligence block at all: what a plain advisory database returns.
		}},
	}}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	f := vulnFinding(t, fs)
	if f.Severity != findings.SeverityCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if got := f.Metadata["vuln_status"]; got != string(vulnsource.StatusPublished) {
		t.Errorf("vuln_status = %q, want PUBLISHED", got)
	}
	if !strings.HasPrefix(f.Message, "Known vulnerability") {
		t.Errorf("message = %q, want the published wording", f.Message)
	}
}

// A candidate is reported, labelled THEORETICAL, and demoted out of gating
// severity — reported so it is not lost, demoted so one false positive cannot
// train an operator to ignore the whole class.
func TestStatus_CandidateIsReportedButDoesNotGate(t *testing.T) {
	src := &stubSource{name: "nox-intel", records: map[string][]vulnsource.Record{
		"lodash": {{
			ID:       "NOX-CAND-abc123",
			Summary:  "Suspected deserialization flaw",
			Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
			Intelligence: &vulnsource.Intelligence{
				Status:        vulnsource.StatusCandidate,
				Corroboration: 4,
				SourceName:    "nox-intel",
			},
		}},
	}}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	f := vulnFinding(t, fs)
	if f.Severity != findings.SeverityInfo {
		t.Errorf("severity = %v, want info — a 9.8 candidate must not gate", f.Severity)
	}
	if !strings.HasPrefix(f.Message, "THEORETICAL") {
		t.Errorf("message = %q, want it to open with THEORETICAL", f.Message)
	}
	if got := f.Metadata["vuln_status"]; got != string(vulnsource.StatusCandidate) {
		t.Errorf("vuln_status = %q, want CANDIDATE", got)
	}
	if got := f.Metadata["intel_corroboration"]; got != "4" {
		t.Errorf("intel_corroboration = %q, want 4", got)
	}
	if got := f.Metadata["intel_source"]; got != "nox-intel" {
		t.Errorf("intel_source = %q, want nox-intel", got)
	}
}

// A status this build does not recognise must not obtain gating standing. A
// source cannot promote its own claim by sending an unfamiliar word.
func TestStatus_UnknownStatusFailsClosed(t *testing.T) {
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"lodash": {{
			ID:           "WEIRD-1",
			Summary:      "who knows",
			Severity:     []vulnsource.Severity{{Type: "CVSS_V3", Score: "9.8"}},
			Intelligence: &vulnsource.Intelligence{Status: vulnsource.Status("TOTALLY_REAL")},
		}},
	}}

	_, artifacts := npmLockfile(t, "lodash", "4.17.20")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	if f := vulnFinding(t, fs); f.Severity != findings.SeverityInfo {
		t.Errorf("severity = %v, want info — an unrecognised status must not gate", f.Severity)
	}
}

// vulnFinding returns the single VULN-001 finding, failing if there is not
// exactly one.
func vulnFinding(t *testing.T, fs *findings.FindingSet) findings.Finding {
	t.Helper()
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 VULN-001 finding, got %d", len(out))
	}
	return out[0]
}
