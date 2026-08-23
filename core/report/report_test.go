package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// sampleFindingSet returns a FindingSet with two findings added in reverse
// order (rule-002 before rule-001) so tests can verify deterministic sorting.
func sampleFindingSet() *findings.FindingSet {
	fs := findings.NewFindingSet()

	fs.Add(findings.Finding{
		ID:         "f-2",
		RuleID:     "rule-002",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceHigh,
		Location: findings.Location{
			FilePath:    "pkg/auth/handler.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   35,
		},
		Message:  "Insecure comparison of secret token",
		Metadata: map[string]string{"category": "crypto"},
	})

	fs.Add(findings.Finding{
		ID:         "f-1",
		RuleID:     "rule-001",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location: findings.Location{
			FilePath:    "cmd/server/main.go",
			StartLine:   15,
			EndLine:     15,
			StartColumn: 1,
			EndColumn:   40,
		},
		Message:  "Hardcoded credential detected",
		Metadata: map[string]string{"category": "secrets"},
	})

	return fs
}

func TestGenerateProducesValidJSON(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generate produced invalid JSON: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}
}

func TestGenerateContainsCorrectMeta(t *testing.T) {
	r := NewJSONReporter("1.2.3")
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if report.Meta.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %q", report.Meta.SchemaVersion)
	}
	if report.Meta.ToolName != "nox" {
		t.Errorf("expected tool name nox, got %q", report.Meta.ToolName)
	}
	if report.Meta.ToolVersion != "1.2.3" {
		t.Errorf("expected tool version 1.2.3, got %q", report.Meta.ToolVersion)
	}
	if report.Meta.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be non-empty")
	}
}

func TestGenerateOfflineAttestation(t *testing.T) {
	// Default: a reporter records offline=false, so an artifact never over-claims
	// a zero-network scan that wasn't one.
	def, err := NewJSONReporter("1.0.0").Generate(sampleFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var defReport JSONReport
	if err := json.Unmarshal(def, &defReport); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if defReport.Meta.Offline {
		t.Error("default reporter must record offline=false")
	}

	// With Offline set, the attestation appears in the artifact so a reviewer
	// can confirm the scan touched no network straight from findings.json.
	r := NewJSONReporter("1.0.0")
	r.Offline = true
	data, err := r.Generate(sampleFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !report.Meta.Offline {
		t.Error("offline reporter must record offline=true in meta")
	}
	if !bytes.Contains(data, []byte(`"offline": true`)) {
		t.Errorf("findings.json meta must carry the offline attestation; got: %s", data)
	}
}

func TestGenerateSASTLanguagesMeta(t *testing.T) {
	// Default: no profile set, so the field is omitted from the artifact rather
	// than emitting a null/empty object.
	def, err := NewJSONReporter("1.0.0").Generate(sampleFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bytes.Contains(def, []byte("sast_languages")) {
		t.Errorf("empty profile must be omitted from meta; got: %s", def)
	}

	// With a resolved profile, the depth strategy is recorded so a reviewer can
	// audit which languages were scanned at which depth straight from the report.
	r := NewJSONReporter("1.0.0")
	r.SASTLanguages = map[string]string{"python": "deep", "go": "standard", "rust": "off"}
	data, err := r.Generate(sampleFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.Meta.SASTLanguages["python"] != "deep" {
		t.Errorf("meta sast_languages[python] = %q, want deep", report.Meta.SASTLanguages["python"])
	}
	if report.Meta.SASTLanguages["rust"] != "off" {
		t.Errorf("meta sast_languages[rust] = %q, want off", report.Meta.SASTLanguages["rust"])
	}
}

func TestGenerateSortsFindingsDeterministically(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	// Findings are added in reverse order (rule-002 before rule-001).
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(report.Findings))
	}

	// After deterministic sorting, rule-001 must come before rule-002.
	if report.Findings[0].RuleID != "rule-001" {
		t.Errorf("expected first finding rule-001, got %q", report.Findings[0].RuleID)
	}
	if report.Findings[1].RuleID != "rule-002" {
		t.Errorf("expected second finding rule-002, got %q", report.Findings[1].RuleID)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	// Generate twice from the same input and verify the output is identical
	// after stripping the GeneratedAt field which depends on wall-clock time.
	r := NewJSONReporter("0.1.0")

	fs1 := sampleFindingSet()
	data1, err := r.Generate(fs1)
	if err != nil {
		t.Fatalf("first Generate returned error: %v", err)
	}

	fs2 := sampleFindingSet()
	data2, err := r.Generate(fs2)
	if err != nil {
		t.Fatalf("second Generate returned error: %v", err)
	}

	// Unmarshal both, zero out GeneratedAt, re-marshal for comparison.
	var r1, r2 JSONReport
	if err := json.Unmarshal(data1, &r1); err != nil {
		t.Fatalf("unmarshal r1: %v", err)
	}
	if err := json.Unmarshal(data2, &r2); err != nil {
		t.Fatalf("unmarshal r2: %v", err)
	}

	r1.Meta.GeneratedAt = ""
	r2.Meta.GeneratedAt = ""

	norm1, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("re-marshal r1: %v", err)
	}
	norm2, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("re-marshal r2: %v", err)
	}

	if !bytes.Equal(norm1, norm2) {
		t.Errorf("outputs are not deterministic:\n  first:  %s\n  second: %s", norm1, norm2)
	}
}

func TestWriteToFileCreatesValidFile(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := sampleFindingSet()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := r.WriteToFile(fs, path); err != nil {
		t.Fatalf("WriteToFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read written file: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("written file contains invalid JSON: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings in written file, got %d", len(report.Findings))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("could not stat written file: %v", err)
	}
	// Verify file permissions (Windows does not support Unix permission bits).
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0o644 {
			t.Errorf("expected file permissions 0644, got %04o", perm)
		}
	}
}

func TestEmptyFindingSetProducesValidJSON(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := findings.NewFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generate produced invalid JSON for empty set: %v", err)
	}

	if report.Findings == nil {
		t.Error("expected Findings to be non-nil empty slice, got nil")
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(report.Findings))
	}
}

func TestWriteToFile_ErrorOnInvalidPath(t *testing.T) {
	r := NewJSONReporter("0.1.0")
	fs := sampleFindingSet()

	// Writing to a path inside a nonexistent directory should fail.
	err := r.WriteToFile(fs, "/nonexistent/dir/report.json")
	if err == nil {
		t.Fatal("expected error writing to invalid path, got nil")
	}
}

// Enrichments were populated on ScanResult and then dropped: no reporter
// serialized them, so a post-scan plugin's entire output was computed and
// discarded. That made a plugin which annotates rather than detects — the
// correct shape for triage and threat-intel — indistinguishable from one that
// never ran, for any consumer reading findings.json.
func TestJSONReporter_SerializesEnrichments(t *testing.T) {
	fs := findings.NewFindingSet()
	r := NewJSONReporter("test")
	r.Enrichments = []findings.Enrichment{{
		FindingFingerprint: "abc123",
		Kind:               "triage",
		Title:              "Triage: immediate",
		Body:               "**Priority: immediate**",
		Metadata:           map[string]string{"priority": "immediate", "rank": "0"},
		Source:             "nox/triage-agent",
	}}

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var got struct {
		Enrichments []struct {
			FindingFingerprint string            `json:"finding_fingerprint"`
			Kind               string            `json:"kind"`
			Metadata           map[string]string `json:"metadata"`
			Source             string            `json:"source"`
		} `json:"enrichments"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Enrichments) != 1 {
		t.Fatalf("expected the enrichment to reach the artifact, got %d", len(got.Enrichments))
	}
	e := got.Enrichments[0]
	// The fingerprint is the whole link. Without it the annotation cannot be
	// attached to anything, whatever else survives serialization.
	if e.FindingFingerprint != "abc123" {
		t.Errorf("finding_fingerprint = %q, want abc123", e.FindingFingerprint)
	}
	if e.Kind != "triage" || e.Source != "nox/triage-agent" {
		t.Errorf("kind/source lost: %q / %q", e.Kind, e.Source)
	}
	if e.Metadata["priority"] != "immediate" {
		t.Errorf("metadata lost: %v", e.Metadata)
	}
}

// A scan with no post-scan plugins must be byte-identical to before, so the
// key is omitted rather than emitted as null or [].
func TestJSONReporter_OmitsEnrichmentsWhenEmpty(t *testing.T) {
	data, err := NewJSONReporter("test").Generate(findings.NewFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(string(data), "enrichments") {
		t.Errorf("empty enrichments must be omitted entirely, got:\n%s", data)
	}
}

func TestLoadFindingsFileParsesTheRealArtifact(t *testing.T) {
	// A real `nox scan` writes a JSON OBJECT ({meta, findings, ...}), not an
	// array. The vex init loader had drifted to parsing an array, which failed
	// against every real scan. This asserts the shared loader reads the object.
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	fs := findings.NewFindingSet()
	fs.Add(findings.NewFinding("SEC-001", findings.SeverityHigh, findings.ConfidenceHigh,
		findings.Location{FilePath: "config.env", StartLine: 1, EndLine: 1}, "secret"))
	data, err := NewJSONReporter("test").Generate(fs)
	if err != nil {
		t.Fatalf("building report: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	got, err := LoadFindingsFile(path)
	if err != nil {
		t.Fatalf("LoadFindingsFile on a real scan artifact failed: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "SEC-001" {
		t.Fatalf("loaded %d findings, want 1 SEC-001: %+v", len(got), got)
	}

	// And the report projects active findings.
	full, err := LoadFindingsFileReport(path)
	if err != nil {
		t.Fatalf("LoadFindingsFileReport: %v", err)
	}
	if len(full.ActiveFindings()) != 1 {
		t.Fatalf("ActiveFindings = %d, want 1", len(full.ActiveFindings()))
	}
}
