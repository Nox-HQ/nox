package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/intel"
)

func TestParsePackageRef(t *testing.T) {
	tests := []struct {
		name                    string
		ref                     string
		ecosystem, pkg, version string
	}{
		{"full", "npm:left-pad@1.3.0", "npm", "left-pad", "1.3.0"},
		{"no version", "go:github.com/foo/bar", "go", "github.com/foo/bar", ""},
		{"no ecosystem", "left-pad@1.3.0", "", "left-pad", "1.3.0"},
		{"bare name", "left-pad", "", "left-pad", ""},
		// A scoped npm name starts with @; splitting on the FIRST @ would turn
		// "@acme/widget" into package "" and version "acme/widget".
		{"scoped npm without version", "npm:@acme/widget", "npm", "@acme/widget", ""},
		{"scoped npm with version", "npm:@acme/widget@2.1.0", "npm", "@acme/widget", "2.1.0"},
		// A go module path contains slashes and may carry a major-version suffix.
		{"go module with major", "go:go.klarlabs.de/mcp/v2@1.24.1", "go", "go.klarlabs.de/mcp/v2", "1.24.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, pkg, ver := parsePackageRef(tt.ref)
			if eco != tt.ecosystem || pkg != tt.pkg || ver != tt.version {
				t.Errorf("parsePackageRef(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.ref, eco, pkg, ver, tt.ecosystem, tt.pkg, tt.version)
			}
		})
	}
}

func TestWeaknessClassFor(t *testing.T) {
	tests := []struct {
		ruleID string
		want   intel.WeaknessClass
	}{
		{"VULN-001", "known-vulnerable-dependency"},
		{"MAL-002", "malicious-package"},
		{"AI-PI-001", "prompt-injection"},
		{"AGENTFLOW-001", "prompt-injection"},
		{"TAINT-AI-001", "prompt-injection"},
		{"AGENTFLOW-007", "unsafe-tool-exposure"},
		// A secret on line 42 of a private file is not intelligence about
		// anything shareable, and must not become an observation.
		{"SEC-001", ""},
		{"IAC-100", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := weaknessClassFor(findings.Finding{RuleID: tt.ruleID})
			if got != tt.want {
				t.Errorf("weaknessClassFor(%s) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestObservationsFromKeepsOnlyShareableFindings(t *testing.T) {
	fs := []findings.Finding{
		{
			RuleID:     "VULN-001",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: "/Users/alice/secret/go.mod", StartLine: 12},
			Message:    "left-pad 1.0.0 is vulnerable",
			Metadata:   map[string]string{"ecosystem": "npm", "package": "left-pad", "version": "1.0.0"},
		},
		{
			RuleID:     "SEC-001",
			Severity:   findings.SeverityCritical,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: "/Users/alice/secret/config.py"},
			Message:    "AWS key AKIAIOSFODNN7EXAMPLE",
		},
	}
	obs := observationsFrom(fs, "src-1", "2026-08-23T00:00:00Z")
	if len(obs) != 1 {
		t.Fatalf("got %d observation(s), want 1 (the secret finding must be dropped)", len(obs))
	}
	if obs[0].Package != "left-pad" || obs[0].Ecosystem != "npm" {
		t.Errorf("observation lost its component identity: %+v", obs[0])
	}
	if obs[0].Fingerprint == "" {
		t.Error("observation was not fingerprinted")
	}
	// A high-confidence analyzer claim is stronger evidence than a pattern hit,
	// and the ledger has to be able to tell them apart.
	if obs[0].Kind != evidence.KindStatic {
		t.Errorf("Kind = %s, want %s for a high-confidence finding", obs[0].Kind, evidence.KindStatic)
	}

	// Nothing from the source tree may survive into an observation.
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshalling observations: %v", err)
	}
	for _, leak := range []string{"/Users/alice", "config.py", "AKIAIOSFODNN7EXAMPLE", "go.mod"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("observation leaked %q into %s", leak, raw)
		}
	}
}

func TestObservationsFromDowngradesLowConfidenceToHeuristic(t *testing.T) {
	obs := observationsFrom([]findings.Finding{{
		RuleID:     "VULN-001",
		Confidence: findings.ConfidenceLow,
		Metadata:   map[string]string{"ecosystem": "npm", "package": "left-pad", "version": "1.0.0"},
	}}, "src-1", "2026-08-23T00:00:00Z")
	if len(obs) != 1 {
		t.Fatalf("got %d observation(s), want 1", len(obs))
	}
	if obs[0].Kind != evidence.KindHeuristic {
		t.Errorf("Kind = %s, want %s for a low-confidence finding", obs[0].Kind, evidence.KindHeuristic)
	}
}

func TestVersionSuffix(t *testing.T) {
	if got := versionSuffix(""); got != "" {
		t.Errorf("versionSuffix(\"\") = %q, want \"\"", got)
	}
	if got := versionSuffix("1.2.3"); got != "@1.2.3" {
		t.Errorf("versionSuffix(\"1.2.3\") = %q, want \"@1.2.3\"", got)
	}
}

func TestExploitEvidenceFromTrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attack.trace.json")
	doc := `{
      "generated_at": "2026-08-23T00:00:00Z",
      "traces": [
        {
          "id": "TRACE-1",
          "exploitability": "CONFIRMED",
          "finding_fingerprints": ["fp-a", "fp-b"],
          "reproduction_hits": 3,
          "reproduction_samples": 3,
          "ledger": {"claims": [{"kind": "dynamic_exploit"}]}
        },
        {
          "id": "TRACE-2",
          "exploitability": "INCONCLUSIVE",
          "reproduction_hits": 1,
          "reproduction_samples": 3,
          "ledger": {"claims": [{"kind": "semantic"}]}
        }
      ]
    }`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	evs, err := exploitEvidenceFrom(path)
	if err != nil {
		t.Fatalf("exploitEvidenceFrom: %v", err)
	}
	// TRACE-1 carries two fingerprints, so it yields one item per fingerprint.
	if len(evs) != 3 {
		t.Fatalf("got %d evidence item(s), want 3", len(evs))
	}
	if !evs[0].Deterministic || !evs[0].Reproduced {
		t.Errorf("a dynamic_exploit trace at 3/3 should be deterministic and reproduced: %+v", evs[0])
	}
	if evs[0].Exploitability != evidence.Confirmed {
		t.Errorf("Exploitability = %s, want CONFIRMED", evs[0].Exploitability)
	}
	// A semantic-only, unreproduced trace must carry neither flag — this is what
	// stops an LLM's opinion from validating a candidate downstream.
	last := evs[len(evs)-1]
	if last.Deterministic {
		t.Error("a semantic-only trace must not be marked deterministic")
	}
	if last.Reproduced {
		t.Error("a 1-of-3 trace must not be marked reproduced")
	}
}

func TestExploitEvidenceFromRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := exploitEvidenceFrom(path); err == nil {
		t.Fatal("expected an error for a malformed trace file")
	}
	if _, err := exploitEvidenceFrom(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected an error for a missing trace file")
	}
}
