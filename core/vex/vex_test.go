package vex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestLoadVEX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vex.json")
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "test-vex",
		"statements": [
			{
				"vulnerability": "CVE-2024-1234",
				"status": "not_affected",
				"justification": "component_not_present"
			},
			{
				"vulnerability": "CVE-2024-5678",
				"status": "under_investigation"
			}
		]
	}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadVEX(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}

	if doc.Statements[0].VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("unexpected vuln ID: %s", doc.Statements[0].VulnerabilityID)
	}

	if doc.Statements[0].Status != StatusNotAffected {
		t.Errorf("unexpected status: %s", doc.Statements[0].Status)
	}
}

func TestLoadVEX_FileNotFound(t *testing.T) {
	_, err := LoadVEX("/nonexistent/vex.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadVEX_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{invalid`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadVEX(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestApplyVEX(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityHigh,
		Message:  "CVE-2024-1234 in lodash@4.17.20",
		Metadata: map[string]string{
			"vuln_id":   "GHSA-xxxx",
			"aliases":   "CVE-2024-1234",
			"package":   "lodash",
			"version":   "4.17.20",
			"ecosystem": "npm",
		},
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 1},
	})
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityMedium,
		Message:  "CVE-2024-9999 in express@4.0",
		Metadata: map[string]string{
			"vuln_id":   "CVE-2024-9999",
			"package":   "express",
			"version":   "4.0",
			"ecosystem": "npm",
		},
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 2},
	})
	fs.Add(findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Message:  "AWS key detected",
		Location: findings.Location{FilePath: "config.env", StartLine: 3},
	})

	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-2024-1234", Status: StatusNotAffected, Justification: "inline_mitigations_already_exist"},
			{VulnerabilityID: "CVE-2024-5678", Status: StatusFixed},
		},
	}

	applied := ApplyVEX(fs, doc)

	if applied != 1 {
		t.Errorf("expected 1 applied, got %d", applied)
	}

	items := fs.Findings()
	if items[0].Status != findings.StatusVEXNotAffected {
		t.Errorf("expected VEX not_affected status, got %q", items[0].Status)
	}

	// Second VULN-001 should be unchanged (no matching VEX statement).
	if items[1].Status == findings.StatusVEXNotAffected {
		t.Error("second finding should not be VEX-marked")
	}

	// SEC-001 should be unchanged.
	if items[2].Status == findings.StatusVEXNotAffected {
		t.Error("non-VULN finding should not be VEX-marked")
	}
}

func TestApplyVEX_NilDocument(t *testing.T) {
	fs := findings.NewFindingSet()
	applied := ApplyVEX(fs, nil)
	if applied != 0 {
		t.Errorf("expected 0 applied, got %d", applied)
	}
}

func TestApplyVEX_MatchesByRuleID(t *testing.T) {
	// Reproduces issue #50: VEX waivers covering nox RuleIDs (e.g.
	// SEC-073, IAC-013) used to be ignored because ApplyVEX only
	// inspected vuln_id metadata. Confirm rule-ID-shaped waivers
	// flip the status now.
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "SEC-073",
		Severity: findings.SeverityCritical,
		Message:  "Postgres conn string",
		Location: findings.Location{FilePath: ".github/workflows/ci.yml", StartLine: 12},
	})
	fs.Add(findings.Finding{
		RuleID:   "IAC-013",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "infra/main.tf", StartLine: 88},
	})

	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "SEC-073", Status: StatusNotAffected},
			{VulnerabilityID: "IAC-013", Status: StatusNotAffected},
		},
	}
	if applied := ApplyVEX(fs, doc); applied != 2 {
		t.Errorf("expected 2 applied, got %d", applied)
	}
	for _, f := range fs.Findings() {
		if f.Status != findings.StatusVEXNotAffected {
			t.Errorf("rule %s: expected not_affected status, got %q", f.RuleID, f.Status)
		}
	}
}

func TestApplyVEX_FingerprintPin(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:      "SEC-073",
		Fingerprint: "abc123",
	})
	fs.Add(findings.Finding{
		RuleID:      "SEC-073",
		Fingerprint: "def456",
	})

	doc := &Document{
		Statements: []Statement{{
			VulnerabilityID: "SEC-073",
			Status:          StatusNotAffected,
			NoxFingerprint:  "abc123",
		}},
	}
	ApplyVEX(fs, doc)

	got := fs.Findings()
	if got[0].Status != findings.StatusVEXNotAffected {
		t.Errorf("fingerprint match should waive abc123, got %q", got[0].Status)
	}
	// def456 finding has the same RuleID; with fingerprint pin
	// preference, it falls through to the rule-ID match (which also
	// hits in this test). The contract is: fingerprint takes
	// precedence, but rule-ID still applies when no fingerprint pin
	// matches.
	if got[1].Status != findings.StatusVEXNotAffected {
		t.Errorf("def456 finding should waive via rule-id fallback, got %q", got[1].Status)
	}
}

func TestApplyVEX_UnderInvestigation(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:   "VULN-001",
		Severity: findings.SeverityHigh,
		Message:  "CVE-2024-5678",
		Metadata: map[string]string{"vuln_id": "CVE-2024-5678"},
		Location: findings.Location{FilePath: "go.sum", StartLine: 1},
	})

	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-2024-5678", Status: StatusUnderInvestigation},
		},
	}

	applied := ApplyVEX(fs, doc)
	if applied != 1 {
		t.Errorf("expected 1 applied, got %d", applied)
	}

	if fs.Findings()[0].Status != findings.StatusVEXUnderInvestigation {
		t.Errorf("expected under_investigation status, got %q", fs.Findings()[0].Status)
	}
}

func TestSummary(t *testing.T) {
	doc := &Document{
		Statements: []Statement{
			{VulnerabilityID: "CVE-1", Status: StatusNotAffected},
			{VulnerabilityID: "CVE-2", Status: StatusNotAffected},
			{VulnerabilityID: "CVE-3", Status: StatusFixed},
		},
	}

	s := Summary(doc)
	if s == "" {
		t.Error("expected non-empty summary")
	}

	if Summary(nil) != "no VEX document" {
		t.Error("expected nil doc message")
	}
}

func TestBuildStub_OneStatementPerFingerprint(t *testing.T) {
	in := []findings.Finding{
		{RuleID: "VULN-001", Fingerprint: "fp1", Location: findings.Location{FilePath: "go.sum", StartLine: 1}},
		{RuleID: "VULN-001", Fingerprint: "fp1", Location: findings.Location{FilePath: "go.sum", StartLine: 1}},
		{RuleID: "VULN-001", Fingerprint: "fp2", Location: findings.Location{FilePath: "package-lock.json", StartLine: 12}},
	}
	doc := BuildStub(in, "github.com/foo/bar")

	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 stub statements, got %d", len(doc.Statements))
	}
	for _, s := range doc.Statements {
		if s.Status != StatusUnderInvestigation {
			t.Errorf("stub status must default to under_investigation, got %s", s.Status)
		}
		if len(s.Products) != 1 || s.Products[0] != "github.com/foo/bar" {
			t.Errorf("expected product to be github.com/foo/bar, got %v", s.Products)
		}
	}
}

func TestBuildStub_DedupesAndAggregatesLocations(t *testing.T) {
	in := []findings.Finding{
		{RuleID: "VULN-001", Fingerprint: "fp1", Location: findings.Location{FilePath: "a", StartLine: 1}},
		{RuleID: "VULN-001", Fingerprint: "fp1", Location: findings.Location{FilePath: "b", StartLine: 2}},
	}
	doc := BuildStub(in, "")

	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	if got := doc.Statements[0].NoxLocations; len(got) != 2 {
		t.Errorf("expected 2 aggregated locations, got %v", got)
	}
}

func TestCollectVulnIDs(t *testing.T) {
	f := findings.Finding{
		Metadata: map[string]string{
			"vuln_id": "GHSA-xxxx",
			"aliases": "CVE-2024-1234,CVE-2024-5678",
		},
	}

	ids := collectVulnIDs(&f)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}

	// No metadata.
	f2 := findings.Finding{}
	ids2 := collectVulnIDs(&f2)
	if len(ids2) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids2))
	}
}

// TestStatement_AcceptsBothOpenVEXShapes covers the regression where a
// spec-current v0.2.0 document was rejected outright. It failed at LOAD time,
// before any scanning, so the practical effect was no scan at all — worse than
// a scan with unapplied waivers, and indistinguishable from a clean one.
func TestStatement_AcceptsBothOpenVEXShapes(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantVuln string
		wantProd []string
	}{
		{
			name:     "v0.1.0 strings",
			json:     `{"vulnerability":"CVE-2024-1234","products":["pkg:golang/example"],"status":"not_affected"}`,
			wantVuln: "CVE-2024-1234",
			wantProd: []string{"pkg:golang/example"},
		},
		{
			name:     "v0.2.0 objects",
			json:     `{"vulnerability":{"@id":"CVE-2024-1234","name":"CVE-2024-1234","description":"x"},"products":[{"@id":"pkg:golang/example"}],"status":"not_affected"}`,
			wantVuln: "CVE-2024-1234",
			wantProd: []string{"pkg:golang/example"},
		},
		{
			name:     "object with only name falls back to it",
			json:     `{"vulnerability":{"name":"AI-036"},"status":"not_affected"}`,
			wantVuln: "AI-036",
		},
		{
			name:     "@id wins over name, being the identity field",
			json:     `{"vulnerability":{"@id":"CVE-2024-1234","name":"friendly label"},"status":"not_affected"}`,
			wantVuln: "CVE-2024-1234",
		},
		{
			name:     "a mixed array is tolerated rather than rejected",
			json:     `{"vulnerability":"CVE-1","products":["pkg:a",{"@id":"pkg:b"}],"status":"fixed"}`,
			wantVuln: "CVE-1",
			wantProd: []string{"pkg:a", "pkg:b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got Statement
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.VulnerabilityID != tc.wantVuln {
				t.Errorf("VulnerabilityID = %q, want %q", got.VulnerabilityID, tc.wantVuln)
			}
			if len(got.Products) != len(tc.wantProd) {
				t.Fatalf("Products = %v, want %v", got.Products, tc.wantProd)
			}
			for i := range tc.wantProd {
				if got.Products[i] != tc.wantProd[i] {
					t.Errorf("Products[%d] = %q, want %q", i, got.Products[i], tc.wantProd[i])
				}
			}
			// The other fields must still decode through the alias.
			if got.Status != Status(map[bool]string{true: "fixed", false: "not_affected"}[tc.wantVuln == "CVE-1"]) {
				t.Errorf("Status = %q — sibling fields must survive the custom unmarshaller", got.Status)
			}
		})
	}
}

// TestStatement_RoundTripsThroughNoxsOwnWriter guards the half the issue also
// flagged: whatever `nox baseline` emits must be readable by `nox scan -vex` in
// the same release, or the two halves disagree.
func TestStatement_RoundTripsThroughNoxsOwnWriter(t *testing.T) {
	orig := Statement{VulnerabilityID: "CVE-2024-9999", Status: StatusNotAffected, Products: []string{"pkg:golang/x"}}
	blob, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Statement
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("nox cannot read what nox wrote: %v", err)
	}
	if back.VulnerabilityID != orig.VulnerabilityID || len(back.Products) != 1 || back.Products[0] != orig.Products[0] {
		t.Errorf("round trip lost data: %+v", back)
	}
}

// TestApplyVEX_RetiredRuleID: a statement naming a rule ID that has since been
// retired into another rule still applies to the surviving finding — otherwise
// retiring a duplicate ID re-opens everything waived under it.
func TestApplyVEX_RetiredRuleID(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:         "IAC-018",
		Fingerprint:    "current-fp",
		Message:        "Workflow step suppresses failures with continue-on-error",
		RetiredRuleIDs: []string{"IAC-310"},
	})

	doc := &Document{Statements: []Statement{{
		VulnerabilityID: "IAC-310",
		Status:          StatusNotAffected,
		Justification:   "deliberately non-blocking step",
	}}}
	if applied := ApplyVEX(fs, doc); applied != 1 {
		t.Fatalf("ApplyVEX applied %d statements, want 1", applied)
	}
	if got := fs.Findings()[0].Status; got != findings.StatusVEXNotAffected {
		t.Errorf("status = %q, want %q", got, findings.StatusVEXNotAffected)
	}
}

// TestApplyVEX_RetiredFingerprintPin: the same for an occurrence-pinned
// statement, whose _nox_fingerprint was recorded under the retired ID.
func TestApplyVEX_RetiredFingerprintPin(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:            "IAC-018",
		Fingerprint:       "current-fp",
		Message:           "Workflow step suppresses failures with continue-on-error",
		AliasFingerprints: []string{"legacy-fp"},
	})

	doc := &Document{Statements: []Statement{{
		VulnerabilityID: "IAC-310",
		Status:          StatusFixed,
		NoxFingerprint:  "legacy-fp",
	}}}
	if applied := ApplyVEX(fs, doc); applied != 1 {
		t.Fatalf("ApplyVEX applied %d statements, want 1", applied)
	}
	if got := fs.Findings()[0].Status; got != findings.StatusVEXFixed {
		t.Errorf("status = %q, want %q", got, findings.StatusVEXFixed)
	}
}

// TestApplyVEX_UnrelatedRetiredIDIsNotMatched: the alias is an exact ID list,
// not a family match.
func TestApplyVEX_UnrelatedRetiredIDIsNotMatched(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:         "IAC-018",
		Fingerprint:    "current-fp",
		Message:        "Workflow step suppresses failures with continue-on-error",
		RetiredRuleIDs: []string{"IAC-310"},
	})

	doc := &Document{Statements: []Statement{{
		VulnerabilityID: "IAC-311",
		Status:          StatusNotAffected,
	}}}
	if applied := ApplyVEX(fs, doc); applied != 0 {
		t.Errorf("ApplyVEX applied %d statements for an unrelated ID, want 0", applied)
	}
}
