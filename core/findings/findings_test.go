package findings

import (
	"strconv"
	"testing"
)

// ---------------------------------------------------------------------------
// Fingerprint tests
// ---------------------------------------------------------------------------

func TestComputeFingerprint_Determinism(t *testing.T) {
	t.Parallel()

	loc := Location{
		FilePath:  "cmd/server/main.go",
		StartLine: 42,
	}

	fp1 := ComputeFingerprint("SEC001", loc, "hardcoded credential")
	fp2 := ComputeFingerprint("SEC001", loc, "hardcoded credential")

	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: got %q and %q for identical inputs", fp1, fp2)
	}
}

func TestComputeFingerprint_Uniqueness(t *testing.T) {
	// This test covers the V1 uniqueness axes (rule_id, file_path, start_line,
	// content). Under the default V2 algorithm start_line is intentionally NOT
	// an axis (line-independence is the whole point — see
	// TestFingerprintV2_LineIndependent), so pin V1 here. Not parallel: it
	// mutates the package-global fingerprint version.
	withFingerprintVersion(t, FingerprintV1)

	loc := Location{
		FilePath:  "cmd/server/main.go",
		StartLine: 42,
	}

	tests := []struct {
		name    string
		ruleID  string
		loc     Location
		content string
	}{
		{
			name:    "different rule ID",
			ruleID:  "SEC002",
			loc:     loc,
			content: "hardcoded credential",
		},
		{
			name:   "different file path",
			ruleID: "SEC001",
			loc: Location{
				FilePath:  "cmd/worker/main.go",
				StartLine: 42,
			},
			content: "hardcoded credential",
		},
		{
			name:   "different start line",
			ruleID: "SEC001",
			loc: Location{
				FilePath:  "cmd/server/main.go",
				StartLine: 99,
			},
			content: "hardcoded credential",
		},
		{
			name:    "different content",
			ruleID:  "SEC001",
			loc:     loc,
			content: "leaked API key",
		},
	}

	baseline := ComputeFingerprint("SEC001", loc, "hardcoded credential")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fp := ComputeFingerprint(tt.ruleID, tt.loc, tt.content)
			if fp == baseline {
				t.Fatalf("expected unique fingerprint for %s, got same as baseline: %s", tt.name, fp)
			}
		})
	}
}

func TestComputeFingerprint_IsHexSHA256(t *testing.T) {
	t.Parallel()

	fp := ComputeFingerprint("R1", Location{FilePath: "f.go", StartLine: 1}, "x")

	// SHA-256 hex digest is exactly 64 hex characters.
	if len(fp) != 64 {
		t.Fatalf("expected 64 hex characters, got %d: %q", len(fp), fp)
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("non-hex character %q in fingerprint %q", c, fp)
		}
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Add tests
// ---------------------------------------------------------------------------

func TestFindingSet_Add_ComputesFingerprint(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})

	findings := fs.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Fingerprint == "" {
		t.Fatal("expected fingerprint to be auto-computed, got empty string")
	}
}

func TestFindingSet_Add_PopulatesIDAndEndLine(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		RuleID:   "CONT-001",
		Location: Location{FilePath: "Dockerfile", StartLine: 4},
		Message:  "image not pinned",
	})

	got := fs.Findings()[0]

	if got.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if got.ID != got.RuleID+"-"+got.Fingerprint[:12] {
		t.Errorf("ID format unexpected: got %q want %q", got.ID, got.RuleID+"-"+got.Fingerprint[:12])
	}
	if got.Location.EndLine != got.Location.StartLine {
		t.Errorf("expected EndLine=%d (StartLine), got %d", got.Location.StartLine, got.Location.EndLine)
	}
}

func TestFindingSet_Add_PreservesExistingIDAndEndLine(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		ID:       "preset-id",
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10, EndLine: 12},
		Message:  "secret detected",
	})

	got := fs.Findings()[0]
	if got.ID != "preset-id" {
		t.Errorf("ID mutated: got %q want preset-id", got.ID)
	}
	if got.Location.EndLine != 12 {
		t.Errorf("EndLine mutated: got %d want 12", got.Location.EndLine)
	}
}

func TestFindingSet_Add_PreservesExistingFingerprint(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	custom := "custom-fingerprint-value"
	fs.Add(Finding{
		RuleID:      "SEC001",
		Location:    Location{FilePath: "main.go", StartLine: 10},
		Message:     "secret detected",
		Fingerprint: custom,
	})

	findings := fs.Findings()
	if findings[0].Fingerprint != custom {
		t.Fatalf("expected fingerprint %q, got %q", custom, findings[0].Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Deduplicate tests
// ---------------------------------------------------------------------------

func TestFindingSet_Deduplicate(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	// Add two identical findings -- they will receive the same fingerprint.
	f := Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	}
	fs.Add(f)
	fs.Add(f)

	// Add a distinct finding.
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "main.go", StartLine: 20},
		Message:  "insecure hash",
	})

	if len(fs.Findings()) != 3 {
		t.Fatalf("expected 3 findings before dedup, got %d", len(fs.Findings()))
	}

	fs.Deduplicate()

	if len(fs.Findings()) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d", len(fs.Findings()))
	}
}

// sinkAnchored builds a flow finding shaped like the built-in taint model's:
// located at the sink, with no sink_line metadata.
func sinkAnchored(rule, path string, sinkLine, sourceLine int, sourceVar string) Finding {
	return Finding{
		RuleID:   rule,
		Location: Location{FilePath: path, StartLine: sinkLine},
		Message:  "built-in: " + sourceVar + " reaches a sink",
		Metadata: map[string]string{
			"source_line": strconv.Itoa(sourceLine),
			"source_var":  sourceVar,
		},
	}
}

// sourceAnchored builds a flow finding shaped like the taint-analysis plugin's:
// located at the source, with the sink line carried in metadata.
func sourceAnchored(rule, path string, sinkLine, sourceLine int, sourceVar string) Finding {
	return Finding{
		RuleID:   rule,
		Location: Location{FilePath: path, StartLine: sourceLine},
		Message:  "plugin: " + sourceVar + " flows to a sink",
		Metadata: map[string]string{
			"sink_line":   strconv.Itoa(sinkLine),
			"source_line": strconv.Itoa(sourceLine),
			"source_var":  sourceVar,
		},
	}
}

func TestFindingSet_DeduplicateFlows_CollapsesToSinkAnchor(t *testing.T) {
	t.Parallel()

	for _, order := range []string{"builtin-first", "plugin-first"} {
		t.Run(order, func(t *testing.T) {
			t.Parallel()
			builtin := sinkAnchored("TAINT-001", "sqli.go", 12, 11, "q")
			plugin := sourceAnchored("TAINT-001", "./sqli.go", 12, 11, "q")

			fs := NewFindingSet()
			if order == "builtin-first" {
				fs.Add(builtin)
				fs.Add(plugin)
			} else {
				fs.Add(plugin)
				fs.Add(builtin)
			}
			fs.DeduplicateFlows()

			got := fs.Findings()
			if len(got) != 1 {
				t.Fatalf("one flow reported from both ends must collapse to 1 finding, got %d", len(got))
			}
			// The sink anchor wins regardless of which analyzer reported first:
			// the result must not depend on analyzer ordering.
			if got[0].Location.StartLine != 12 {
				t.Fatalf("kept the finding at line %d, want the sink line 12", got[0].Location.StartLine)
			}
		})
	}
}

func TestFindingSet_DeduplicateFlows_KeepsDistinctFlows(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// Same rule and file, but a different variable, a different source line and
	// a different sink line: three genuinely distinct vulnerabilities.
	fs.Add(sinkAnchored("TAINT-001", "app.go", 12, 11, "q"))
	fs.Add(sourceAnchored("TAINT-001", "app.go", 12, 11, "other"))
	fs.Add(sourceAnchored("TAINT-001", "app.go", 12, 9, "q"))
	fs.Add(sourceAnchored("TAINT-001", "app.go", 40, 11, "q"))

	fs.DeduplicateFlows()

	if len(fs.Findings()) != 4 {
		t.Fatalf("distinct flows must all survive, got %d of 4", len(fs.Findings()))
	}
}

func TestFindingSet_DeduplicateFlows_IgnoresNonFlowFindings(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// No flow metadata at all: two secrets on the same line of the same file
	// under one rule are not a flow and must never be collapsed by this pass.
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 3}, Message: "aws key"})
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 3}, Message: "gcp key"})
	// Partial flow metadata is not enough to identify a flow either.
	fs.Add(Finding{
		RuleID:   "TAINT-001",
		Location: Location{FilePath: "a.go", StartLine: 12},
		Message:  "no source var",
		Metadata: map[string]string{"source_line": "11"},
	})
	fs.Add(Finding{
		RuleID:   "TAINT-001",
		Location: Location{FilePath: "a.go", StartLine: 12},
		Message:  "no source line",
		Metadata: map[string]string{"source_var": "q"},
	})

	fs.DeduplicateFlows()

	if len(fs.Findings()) != 4 {
		t.Fatalf("findings without flow identity must be untouched, got %d of 4", len(fs.Findings()))
	}
}

func TestFindingSet_SuppressDuplicateVulnClass(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// A variants SSTI CVE signature and a taint SSTI sink both fire on the same
	// render_template_string line — the same vulnerability reported twice.
	fs.Add(Finding{
		RuleID:   "VARIANT-005",
		Location: Location{FilePath: "app.py", StartLine: 9},
		Message:  "SSTI variant",
		Metadata: map[string]string{"vuln_class": "ssti"},
	})
	fs.Add(Finding{
		RuleID:   "TAINT-003",
		Location: Location{FilePath: "app.py", StartLine: 9},
		Message:  "taint SSTI",
		Metadata: map[string]string{"vuln_class": "ssti"},
	})

	fs.SuppressDuplicateVulnClass("TAINT-")

	got := fs.Findings()
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after cross-analyzer SSTI dedup, got %d", len(got))
	}
	if got[0].RuleID != "VARIANT-005" {
		t.Fatalf("expected the specific VARIANT-005 signature kept, got %q", got[0].RuleID)
	}
}

func TestFindingSet_SuppressDuplicateVulnClass_KeepsDistinctClass(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// A taint XSS finding co-located with a variants SSTI finding must be kept:
	// different vuln classes are different vulnerabilities.
	fs.Add(Finding{
		RuleID:   "VARIANT-005",
		Location: Location{FilePath: "app.py", StartLine: 9},
		Metadata: map[string]string{"vuln_class": "ssti"},
	})
	fs.Add(Finding{
		RuleID:   "TAINT-003",
		Location: Location{FilePath: "app.py", StartLine: 9},
		Metadata: map[string]string{"vuln_class": "xss"},
	})

	fs.SuppressDuplicateVulnClass("TAINT-")

	if len(fs.Findings()) != 2 {
		t.Fatalf("distinct vuln classes at one span must both survive, got %d", len(fs.Findings()))
	}
}

func TestFindingSet_SuppressDuplicateVulnClass_KeepsLoneTaint(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// A taint SSTI finding with no other analyzer covering it must be kept.
	fs.Add(Finding{
		RuleID:   "TAINT-003",
		Location: Location{FilePath: "app.py", StartLine: 9},
		Metadata: map[string]string{"vuln_class": "ssti"},
	})

	fs.SuppressDuplicateVulnClass("TAINT-")

	if len(fs.Findings()) != 1 {
		t.Fatalf("a lone taint finding must survive, got %d", len(fs.Findings()))
	}
}

func TestFindingSet_Deduplicate_KeepsFirst(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	fs.Add(Finding{
		ID:       "first",
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})
	fs.Add(Finding{
		ID:       "second",
		RuleID:   "SEC001",
		Location: Location{FilePath: "main.go", StartLine: 10},
		Message:  "secret detected",
	})

	fs.Deduplicate()

	findings := fs.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "first" {
		t.Fatalf("expected first occurrence to be kept, got ID=%q", findings[0].ID)
	}
}

func TestFindingSet_Deduplicate_Empty(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Deduplicate()

	if len(fs.Findings()) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs.Findings()))
	}
}

// ---------------------------------------------------------------------------
// FindingSet.SortDeterministic tests
// ---------------------------------------------------------------------------

func TestFindingSet_SortDeterministic(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	// Add findings in intentionally non-sorted order.
	fs.Add(Finding{
		RuleID:   "SEC003",
		Location: Location{FilePath: "z.go", StartLine: 1},
		Message:  "third rule",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "b.go", StartLine: 50},
		Message:  "first rule, second file",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 30},
		Message:  "first rule, first file, second line",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 10},
		Message:  "first rule, first file, first line",
	})
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "a.go", StartLine: 1},
		Message:  "second rule",
	})

	fs.SortDeterministic()

	findings := fs.Findings()

	expected := []struct {
		ruleID    string
		filePath  string
		startLine int
	}{
		{"SEC001", "a.go", 10},
		{"SEC001", "a.go", 30},
		{"SEC001", "b.go", 50},
		{"SEC002", "a.go", 1},
		{"SEC003", "z.go", 1},
	}

	if len(findings) != len(expected) {
		t.Fatalf("expected %d findings, got %d", len(expected), len(findings))
	}

	for i, want := range expected {
		got := findings[i]
		if got.RuleID != want.ruleID || got.Location.FilePath != want.filePath || got.Location.StartLine != want.startLine {
			t.Errorf("index %d: want (%s, %s, %d), got (%s, %s, %d)",
				i, want.ruleID, want.filePath, want.startLine,
				got.RuleID, got.Location.FilePath, got.Location.StartLine)
		}
	}
}

func TestFindingSet_SortDeterministic_Idempotent(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{
		RuleID:   "SEC002",
		Location: Location{FilePath: "b.go", StartLine: 5},
		Message:  "b",
	})
	fs.Add(Finding{
		RuleID:   "SEC001",
		Location: Location{FilePath: "a.go", StartLine: 1},
		Message:  "a",
	})

	fs.SortDeterministic()
	first := make([]Finding, len(fs.Findings()))
	copy(first, fs.Findings())

	fs.SortDeterministic()
	second := fs.Findings()

	for i := range first {
		if first[i].Fingerprint != second[i].Fingerprint {
			t.Fatalf("sort is not idempotent at index %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Findings tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// FindingSet.RemoveByRuleIDs tests
// ---------------------------------------------------------------------------

func TestFindingSet_RemoveByRuleIDs(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "secret"})
	fs.Add(Finding{RuleID: "AI-008", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "unpinned model"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "c.go", StartLine: 3}, Message: "weak hash"})
	fs.Add(Finding{RuleID: "AI-008", Location: Location{FilePath: "d.go", StartLine: 4}, Message: "unpinned model 2"})

	fs.RemoveByRuleIDs([]string{"AI-008"})

	findings := fs.Findings()
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings after removal, got %d", len(findings))
	}
	for _, f := range findings {
		if f.RuleID == "AI-008" {
			t.Errorf("found AI-008 finding that should have been removed")
		}
	}
}

// Regression: analyzer_rules rule IDs may be wildcards (e.g. "VULN-*").
// Previously RemoveByRuleIDsAndPaths did an exact map lookup so wildcards
// never matched.
func TestFindingSet_RemoveByRuleIDsAndPaths_Wildcard(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "VULN-001", Location: Location{FilePath: "vendor/x.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "VULN-042", Location: Location{FilePath: "vendor/y.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "VULN-001", Location: Location{FilePath: "src/main.go", StartLine: 3}, Message: "c"})
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "vendor/z.go", StartLine: 4}, Message: "d"})

	// Remove all VULN-* findings under vendor/, leaving the src VULN and the SEC.
	fs.RemoveByRuleIDsAndPaths([]string{"VULN-*"}, []string{"vendor/*"})

	got := fs.Findings()
	if len(got) != 2 {
		t.Fatalf("expected 2 findings after wildcard removal, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.RuleID == "VULN-001" && f.Location.FilePath == "src/main.go" {
			continue
		}
		if f.RuleID == "SEC-001" {
			continue
		}
		t.Errorf("unexpected surviving finding %s @ %s", f.RuleID, f.Location.FilePath)
	}
}

func TestFindingSet_RemoveByRuleIDs_Multiple(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "SEC-003", Location: Location{FilePath: "c.go", StartLine: 3}, Message: "c"})

	fs.RemoveByRuleIDs([]string{"SEC-001", "SEC-003"})

	findings := fs.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "SEC-002" {
		t.Errorf("expected SEC-002, got %s", findings[0].RuleID)
	}
}

func TestFindingSet_RemoveByRuleIDs_Empty(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})

	fs.RemoveByRuleIDs(nil)

	if len(fs.Findings()) != 1 {
		t.Fatalf("expected no change with nil ids, got %d findings", len(fs.Findings()))
	}
}

func TestFindingSet_RemoveByRuleIDs_NoMatch(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})

	fs.RemoveByRuleIDs([]string{"NONEXISTENT"})

	if len(fs.Findings()) != 1 {
		t.Fatalf("expected no change for non-matching ids, got %d findings", len(fs.Findings()))
	}
}

// ---------------------------------------------------------------------------
// FindingSet.OverrideSeverity tests
// ---------------------------------------------------------------------------

func TestFindingSet_OverrideSeverity(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "SEC-002", Severity: SeverityCritical, Location: Location{FilePath: "c.go", StartLine: 3}, Message: "c"})

	fs.OverrideSeverity("SEC-001", SeverityMedium)

	for _, f := range fs.Findings() {
		if f.RuleID == "SEC-001" && f.Severity != SeverityMedium {
			t.Errorf("SEC-001 severity = %q, want %q", f.Severity, SeverityMedium)
		}
		if f.RuleID == "SEC-002" && f.Severity != SeverityCritical {
			t.Errorf("SEC-002 severity should be unchanged, got %q", f.Severity)
		}
	}
}

func TestFindingSet_OverrideSeverity_NoMatch(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})

	fs.OverrideSeverity("NONEXISTENT", SeverityLow)

	if fs.Findings()[0].Severity != SeverityHigh {
		t.Errorf("severity should be unchanged, got %q", fs.Findings()[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// FindingSet.Findings tests
// ---------------------------------------------------------------------------

func TestFindingSet_Findings_ReturnsEmptySliceOnNew(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	findings := fs.Findings()

	if findings != nil {
		t.Fatalf("expected nil slice for new FindingSet, got length %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// FindingSet.SetStatus tests
// ---------------------------------------------------------------------------

func TestFindingSet_SetStatus(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "SEC-003", Location: Location{FilePath: "c.go", StartLine: 3}, Message: "c"})

	fs.SetStatus(0, StatusSuppressed)
	fs.SetStatus(1, StatusBaselined)

	findings := fs.Findings()
	if findings[0].Status != StatusSuppressed {
		t.Errorf("expected findings[0].Status to be %q, got %q", StatusSuppressed, findings[0].Status)
	}
	if findings[1].Status != StatusBaselined {
		t.Errorf("expected findings[1].Status to be %q, got %q", StatusBaselined, findings[1].Status)
	}
	if findings[2].Status != "" {
		t.Errorf("expected findings[2].Status to be empty, got %q", findings[2].Status)
	}
}

func TestFindingSet_SetStatus_OutOfBounds(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})

	// Setting status on out-of-bounds indices should not panic.
	fs.SetStatus(-1, StatusSuppressed)
	fs.SetStatus(10, StatusSuppressed)

	// Original finding should be unchanged.
	if fs.Findings()[0].Status != "" {
		t.Errorf("expected original finding status to be unchanged, got %q", fs.Findings()[0].Status)
	}
}

func TestFindingSet_SetStatus_EmptySet(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()

	// Should not panic.
	fs.SetStatus(0, StatusSuppressed)
}

// ---------------------------------------------------------------------------
// FindingSet.CountByStatus tests
// ---------------------------------------------------------------------------

func TestFindingSet_CountByStatus(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a", Status: StatusNew})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b", Status: StatusNew})
	fs.Add(Finding{RuleID: "SEC-003", Location: Location{FilePath: "c.go", StartLine: 3}, Message: "c", Status: StatusBaselined})
	fs.Add(Finding{RuleID: "SEC-004", Location: Location{FilePath: "d.go", StartLine: 4}, Message: "d", Status: StatusSuppressed})
	fs.Add(Finding{RuleID: "SEC-005", Location: Location{FilePath: "e.go", StartLine: 5}, Message: "e", Status: StatusSuppressed})

	counts := fs.CountByStatus()

	if counts[StatusNew] != 2 {
		t.Errorf("expected 2 new findings, got %d", counts[StatusNew])
	}
	if counts[StatusBaselined] != 1 {
		t.Errorf("expected 1 baselined finding, got %d", counts[StatusBaselined])
	}
	if counts[StatusSuppressed] != 2 {
		t.Errorf("expected 2 suppressed findings, got %d", counts[StatusSuppressed])
	}
}

func TestFindingSet_CountByStatus_EmptyStatusDefaultsToNew(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b"})

	counts := fs.CountByStatus()

	if counts[StatusNew] != 2 {
		t.Errorf("expected 2 new findings (empty status defaults to new), got %d", counts[StatusNew])
	}
}

func TestFindingSet_CountByStatus_Empty(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	counts := fs.CountByStatus()

	if len(counts) != 0 {
		t.Errorf("expected empty counts map, got %d entries", len(counts))
	}
}

// ---------------------------------------------------------------------------
// FindingSet.ActiveFindings tests
// ---------------------------------------------------------------------------

func TestFindingSet_ActiveFindings(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a", Status: StatusNew})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b", Status: StatusBaselined})
	fs.Add(Finding{RuleID: "SEC-003", Location: Location{FilePath: "c.go", StartLine: 3}, Message: "c", Status: StatusSuppressed})
	fs.Add(Finding{RuleID: "SEC-004", Location: Location{FilePath: "d.go", StartLine: 4}, Message: "d"})

	active := fs.ActiveFindings()

	if len(active) != 2 {
		t.Fatalf("expected 2 active findings, got %d", len(active))
	}

	// Verify the active findings are the new/empty status ones.
	foundNew := false
	foundEmpty := false
	for _, f := range active {
		if f.RuleID == "SEC-001" && f.Status == StatusNew {
			foundNew = true
		}
		if f.RuleID == "SEC-004" && f.Status == "" {
			foundEmpty = true
		}
	}

	if !foundNew {
		t.Error("expected SEC-001 (StatusNew) in active findings")
	}
	if !foundEmpty {
		t.Error("expected SEC-004 (empty status) in active findings")
	}
}

func TestFindingSet_ActiveFindings_AllSuppressed(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a", Status: StatusSuppressed})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b", Status: StatusBaselined})

	active := fs.ActiveFindings()

	if len(active) != 0 {
		t.Fatalf("expected 0 active findings, got %d", len(active))
	}
}

func TestFindingSet_ActiveFindings_AllActive(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "a", Status: StatusNew})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "b"})

	active := fs.ActiveFindings()

	if len(active) != 2 {
		t.Fatalf("expected 2 active findings, got %d", len(active))
	}
}

func TestFindingSet_ActiveFindings_Empty(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	active := fs.ActiveFindings()

	if active != nil {
		t.Fatalf("expected nil slice for empty set, got %v", active)
	}
}

func TestFindingSet_RemoveByRuleIDsAndPaths(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "test/foo.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "test/bar.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "prod/foo.go", StartLine: 3}, Message: "c"})
	fs.Add(Finding{RuleID: "SEC-003", Location: Location{FilePath: "test/foo.go", StartLine: 4}, Message: "d"})

	fs.RemoveByRuleIDsAndPaths([]string{"SEC-001"}, []string{"test/*"})

	findings := fs.Findings()
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings after removal, got %d", len(findings))
	}
	for _, f := range findings {
		if f.RuleID == "SEC-001" && f.Location.FilePath == "test/foo.go" {
			t.Error("expected SEC-001 in test/foo.go to be removed")
		}
		if f.RuleID == "SEC-001" && f.Location.FilePath == "prod/foo.go" {
			if len(findings) == 2 {
				t.Error("SEC-001 in prod/foo.go should remain (path doesn't match)")
			}
		}
	}
}

func TestFindingSet_OverrideSeverityByRulePatternsAndPaths(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "test/foo.go", StartLine: 1}, Message: "a", Severity: SeverityHigh})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "test/bar.go", StartLine: 2}, Message: "b", Severity: SeverityHigh})
	fs.Add(Finding{RuleID: "VULN-001", Location: Location{FilePath: "prod/foo.go", StartLine: 3}, Message: "c", Severity: SeverityCritical})
	fs.Add(Finding{RuleID: "VULN-002", Location: Location{FilePath: "node_modules/foo.js", StartLine: 4}, Message: "d", Severity: SeverityCritical})

	fs.OverrideSeverityByRulePatternsAndPaths([]string{"SEC-*"}, []string{"test/*"}, SeverityLow)
	fs.OverrideSeverityByRulePatternsAndPaths([]string{"VULN-*"}, []string{"node_modules/*"}, SeverityInfo)

	findings := fs.Findings()
	for _, f := range findings {
		if f.RuleID == "SEC-001" && f.Location.FilePath == "test/foo.go" {
			if f.Severity != SeverityLow {
				t.Errorf("expected SEC-001 in test/foo.go to have SeverityLow, got %s", f.Severity)
			}
		}
		if f.RuleID == "VULN-002" && f.Location.FilePath == "node_modules/foo.js" {
			if f.Severity != SeverityInfo {
				t.Errorf("expected VULN-002 in node_modules/foo.js to have SeverityInfo, got %s", f.Severity)
			}
		}
	}
}

func TestFindingSet_OverrideSeverityByRuleIDAndPath(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "src/main.go", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "vendor/lib.go", StartLine: 2}, Message: "b"})
	fs.Add(Finding{RuleID: "SEC-002", Severity: SeverityCritical, Location: Location{FilePath: "src/main.go", StartLine: 3}, Message: "c"})

	fs.OverrideSeverityByRuleIDAndPath("SEC-001", "vendor/*", SeverityLow)

	for _, f := range fs.Findings() {
		switch {
		case f.RuleID == "SEC-001" && f.Location.FilePath == "vendor/lib.go":
			if f.Severity != SeverityLow {
				t.Errorf("SEC-001 in vendor should be low, got %s", f.Severity)
			}
		case f.RuleID == "SEC-001" && f.Location.FilePath == "src/main.go":
			if f.Severity != SeverityHigh {
				t.Errorf("SEC-001 in src should remain high, got %s", f.Severity)
			}
		case f.RuleID == "SEC-002":
			if f.Severity != SeverityCritical {
				t.Errorf("SEC-002 should remain critical, got %s", f.Severity)
			}
		}
	}
}

func TestFindingSet_OverrideSeverityByRuleIDAndPath_NoMatch(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityHigh, Location: Location{FilePath: "src/main.go", StartLine: 1}, Message: "a"})

	fs.OverrideSeverityByRuleIDAndPath("SEC-999", "src/*", SeverityLow)
	fs.OverrideSeverityByRuleIDAndPath("SEC-001", "vendor/*", SeverityLow)

	if fs.Findings()[0].Severity != SeverityHigh {
		t.Errorf("severity should be unchanged, got %s", fs.Findings()[0].Severity)
	}
}

func TestMatchAnyPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		patterns []string
		want     bool
	}{
		// filepath.Match on full path
		{"src/main.go", []string{"src/main.go"}, true},
		{"src/main.go", []string{"src/*.go"}, true},
		// filepath.Match on base name
		{"deeply/nested/file.js", []string{"*.js"}, true},
		// wildcard prefix suffix matching
		{"config/database.yml", []string{"*database.yml"}, true},
		// matchPathPattern with ** glob
		{"a/b/c.go", []string{"a/**/c.go"}, true},
		// no match
		{"src/main.go", []string{"vendor/*"}, false},
		// empty patterns
		{"src/main.go", nil, false},
	}

	for _, tt := range tests {
		got := matchAnyPattern(tt.path, tt.patterns)
		if got != tt.want {
			t.Errorf("matchAnyPattern(%q, %v) = %v, want %v", tt.path, tt.patterns, got, tt.want)
		}
	}
}

func TestMatchPathPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"a/b/c.go", "a/b/c.go", true},
		{"a/b/c.go", "a/*/c.go", true},
		{"a/b/c.go", "a/**/c.go", true},
		{"a/b/c.go", "x/y/z.go", false},
		// pattern longer than path
		{"a/b", "a/b/c/d", false},
		// part index exceeds path length
		{"a", "a/b", false},
	}

	for _, tt := range tests {
		got := matchPathPattern(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("matchPathPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchRulePatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ruleID   string
		patterns []string
		want     bool
	}{
		{"SEC-001", []string{"SEC-001"}, true},
		{"SEC-001", []string{"SEC-002"}, false},
		{"SEC-001", []string{"SEC-*"}, true},
		{"VULN-001", []string{"VULN-*"}, true},
		{"VULN-001", []string{"*VULN*"}, true},
		{"SEC-001", []string{"*SEC*"}, true},
		{"SEC-001", []string{"TEST-001"}, false},
	}

	for _, tt := range tests {
		got := matchRulePatterns(tt.ruleID, tt.patterns)
		if got != tt.want {
			t.Errorf("matchRulePatterns(%q, %v) = %v, want %v", tt.ruleID, tt.patterns, got, tt.want)
		}
	}
}

func TestRemoveByRuleIDsInDirs(t *testing.T) {
	t.Parallel()
	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "AI-006", Location: Location{FilePath: "tests/foo_test.py", StartLine: 1}, Message: "a"})
	fs.Add(Finding{RuleID: "MCP-011", Location: Location{FilePath: "internal/fixtures/x.go", StartLine: 1}, Message: "b"})
	fs.Add(Finding{RuleID: "AI-006", Location: Location{FilePath: "src/app.go", StartLine: 1}, Message: "c"})
	fs.Add(Finding{RuleID: "VULN-001", Location: Location{FilePath: "tests/dep.go", StartLine: 1}, Message: "d"})

	fs.RemoveByRuleIDsInDirs([]string{"AI-*", "MCP-*"}, []string{"tests", "fixtures"})

	kept := map[string]bool{}
	for _, f := range fs.Findings() {
		kept[f.RuleID+"@"+f.Location.FilePath] = true
	}
	if kept["AI-006@tests/foo_test.py"] || kept["MCP-011@internal/fixtures/x.go"] {
		t.Error("content-rule findings in test/fixture dirs should be removed")
	}
	if !kept["AI-006@src/app.go"] {
		t.Error("content-rule finding in src must be kept")
	}
	if !kept["VULN-001@tests/dep.go"] {
		t.Error("non-content-rule (VULN) finding in tests must be kept")
	}
}

func TestSeverityConfidence_IsValid(t *testing.T) {
	t.Parallel()
	if !SeverityHigh.IsValid() || !ConfidenceLow.IsValid() {
		t.Error("defined severity/confidence must be valid")
	}
	if Severity("bogus").IsValid() || Confidence("").IsValid() {
		t.Error("undefined severity/confidence must be invalid")
	}
}

func TestLocation_Normalized(t *testing.T) {
	t.Parallel()
	if got := (Location{StartLine: 5}).Normalized(); got.EndLine != 5 {
		t.Errorf("zero EndLine should default to StartLine, got %d", got.EndLine)
	}
	if got := (Location{StartLine: 5, EndLine: 2}).Normalized(); got.EndLine != 5 {
		t.Errorf("out-of-order EndLine should clamp to StartLine, got %d", got.EndLine)
	}
	if got := (Location{StartLine: 5, EndLine: 9}).Normalized(); got.EndLine != 9 {
		t.Errorf("valid range must be preserved, got %d", got.EndLine)
	}
}

func TestNewFinding_AndValidate(t *testing.T) {
	t.Parallel()
	f := NewFinding("SEC-001", SeverityHigh, ConfidenceMedium, Location{FilePath: "a.go", StartLine: 3}, "secret")
	if f.Location.EndLine != 3 {
		t.Errorf("NewFinding should normalize location, got EndLine=%d", f.Location.EndLine)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("well-formed finding should validate, got %v", err)
	}
	if (Finding{Severity: SeverityHigh, Confidence: ConfidenceLow}).Validate() == nil {
		t.Error("empty RuleID must fail validation")
	}
	if (Finding{RuleID: "X", Severity: "bogus", Confidence: ConfidenceLow}).Validate() == nil {
		t.Error("invalid severity must fail validation")
	}
}

// TestSortByPriority orders the most actionable findings first: severity, then
// reachability (confirmed-reachable up, likely-false-positive unreachable
// down), then confidence, with a stable location tiebreak.
func TestSortByPriority(t *testing.T) {
	fs := NewFindingSet()
	mk := func(id string, sev Severity, reachable string) Finding {
		f := Finding{RuleID: id, Severity: sev, Confidence: ConfidenceHigh, Status: StatusNew,
			Location: Location{FilePath: "a.go", StartLine: 1}, Message: id}
		if reachable != "" {
			f.Metadata = map[string]string{"reachable": reachable}
		}
		return f
	}
	// Added out of priority order on purpose.
	fs.Add(mk("VULN-low", SeverityLow, ""))
	fs.Add(mk("VULN-crit-unreach", SeverityCritical, "false"))
	fs.Add(mk("VULN-crit-reach", SeverityCritical, "true"))
	fs.Add(mk("VULN-high", SeverityHigh, ""))

	fs.SortByPriority()
	got := make([]string, 0, 4)
	for _, f := range fs.Findings() {
		got = append(got, f.RuleID)
	}
	want := []string{"VULN-crit-reach", "VULN-crit-unreach", "VULN-high", "VULN-low"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("priority order = %v, want %v", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Context-gated downgrade tests
// ---------------------------------------------------------------------------

func TestSeverity_Downgraded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   Severity
		want Severity
	}{
		{SeverityCritical, SeverityHigh},
		{SeverityHigh, SeverityMedium},
		{SeverityMedium, SeverityLow},
		{SeverityLow, SeverityInfo},
		{SeverityInfo, SeverityInfo},           // info is the floor (idempotent)
		{Severity("bogus"), Severity("bogus")}, // unknown passes through unchanged
	}
	for _, tc := range cases {
		if got := tc.in.Downgraded(); got != tc.want {
			t.Errorf("Severity(%q).Downgraded() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDowngradeByRulePatternsAndPath_DowngradesAndRecords(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "AI-002", Severity: SeverityHigh, Location: Location{FilePath: "examples/foo.py", StartLine: 1}, Message: "prompt boundary"})

	inExamples := func(p string) bool { return p == "examples/foo.py" }
	n := fs.DowngradeByRulePatternsAndPath([]string{"AI-*"}, inExamples, "non-production")
	if n != 1 {
		t.Fatalf("downgraded count = %d, want 1", n)
	}

	f := fs.Findings()[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium (high downgraded one level)", f.Severity)
	}
	if f.Metadata["original_severity"] != "high" {
		t.Errorf("original_severity = %q, want high", f.Metadata["original_severity"])
	}
	if f.Metadata["context"] != "non-production" {
		t.Errorf("context = %q, want non-production", f.Metadata["context"])
	}
}

func TestDowngradeByRulePatternsAndPath_SkipsNonMatching(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	// Production path — must not downgrade.
	fs.Add(Finding{RuleID: "AI-002", Severity: SeverityHigh, Location: Location{FilePath: "src/foo.py", StartLine: 1}, Message: "prod"})
	// Out-of-scope family in a non-production path — must not downgrade.
	fs.Add(Finding{RuleID: "SEC-001", Severity: SeverityCritical, Location: Location{FilePath: "tests/foo.py", StartLine: 1}, Message: "secret"})

	always := func(string) bool { return true }
	inTests := func(p string) bool { return p == "tests/foo.py" }

	if n := fs.DowngradeByRulePatternsAndPath(ContextRuleScopeFixture(), inTests, "non-production"); n != 0 {
		t.Fatalf("SEC-001 should be out of scope, downgraded %d", n)
	}
	// AI-002 in src is in-scope by family but not by path.
	if n := fs.DowngradeByRulePatternsAndPath([]string{"AI-*"}, func(p string) bool { return p == "examples/x" }, "non-production"); n != 0 {
		t.Fatalf("AI-002 in src should not match path, downgraded %d", n)
	}
	// Sanity: with an always-true matcher AI-002 downgrades but SEC-001 stays out of scope.
	if n := fs.DowngradeByRulePatternsAndPath([]string{"AI-*"}, always, "non-production"); n != 1 {
		t.Fatalf("AI-002 should downgrade exactly once, got %d", n)
	}
	for _, f := range fs.Findings() {
		if f.RuleID == "SEC-001" && f.Severity != SeverityCritical {
			t.Errorf("SEC-001 must remain critical, got %q", f.Severity)
		}
	}
}

func TestDowngradeByRulePatternsAndPath_Idempotent(t *testing.T) {
	t.Parallel()

	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "IAC-010", Severity: SeverityCritical, Location: Location{FilePath: "test/main.tf", StartLine: 1}, Message: "iac"})

	always := func(string) bool { return true }
	first := fs.DowngradeByRulePatternsAndPath([]string{"IAC-*"}, always, "non-production")
	second := fs.DowngradeByRulePatternsAndPath([]string{"IAC-*"}, always, "non-production")
	if first != 1 || second != 0 {
		t.Fatalf("expected first=1 second=0 (idempotent), got first=%d second=%d", first, second)
	}
	f := fs.Findings()[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (single downgrade only)", f.Severity)
	}
	if f.Metadata["original_severity"] != "critical" {
		t.Errorf("original_severity = %q, want critical (unchanged by second pass)", f.Metadata["original_severity"])
	}
}

// ContextRuleScopeFixture returns the in-scope code-pattern families for the
// downgrade, mirroring core.ContextDowngradeRulePatterns without importing the
// core package (findings must not depend on core). SEC-* is deliberately absent.
func ContextRuleScopeFixture() []string {
	return []string{"AI-*", "MCP-*", "AGENT-*", "IAC-*", "TAINT-*", "SLOP-*", "VARIANT-*"}
}

// TestDeduplicate_KeepsDistinctFindingsAtDifferentLines is the regression test
// for a silent finding loss.
//
// The V2 fingerprint is line-independent by design (baseline stability), so an
// analyzer that builds findings directly and lets Add derive the fingerprint
// from a static message gives two genuinely distinct findings in one file the
// same fingerprint. Deduplicate keyed on fingerprint alone then dropped the
// second — a real second MD5 call, a real second hardcoded secret, never
// reported.
func TestDeduplicate_KeepsDistinctFindingsAtDifferentLines(t *testing.T) {
	fs := NewFindingSet()
	// Same rule, same file, same message — differing only in line, exactly the
	// shape a direct-construction analyzer produces for two occurrences.
	fs.Add(Finding{RuleID: "CRYPTO-001", Message: "Use of MD5",
		Location: Location{FilePath: "hash.go", StartLine: 10}})
	fs.Add(Finding{RuleID: "CRYPTO-001", Message: "Use of MD5",
		Location: Location{FilePath: "hash.go", StartLine: 50}})

	fs.Deduplicate()

	if got := len(fs.Findings()); got != 2 {
		t.Errorf("expected both distinct findings to survive dedup, got %d", got)
	}
}

// TestDeduplicate_RemovesTrueDuplicates confirms the fix did not disable dedup:
// two findings identical in rule, location AND fingerprint are still collapsed.
func TestDeduplicate_RemovesTrueDuplicates(t *testing.T) {
	fs := NewFindingSet()
	f := Finding{RuleID: "CRYPTO-001", Message: "Use of MD5",
		Location: Location{FilePath: "hash.go", StartLine: 10}}
	fs.Add(f)
	fs.Add(f)

	fs.Deduplicate()

	if got := len(fs.Findings()); got != 1 {
		t.Errorf("expected a true duplicate to be removed, got %d findings", got)
	}
}

func TestFormatSeverityCounts(t *testing.T) {
	tests := []struct {
		name   string
		counts map[Severity]int
		want   string
	}{
		{"empty is blank", map[Severity]int{}, ""},
		{"all zero is blank", map[Severity]int{SeverityHigh: 0}, ""},
		{"single", map[Severity]int{SeverityHigh: 3}, "3 high"},
		{"canonical order regardless of map order", map[Severity]int{
			SeverityLow: 1, SeverityCritical: 2, SeverityHigh: 5,
		}, "2 critical, 5 high, 1 low"},
		{"omits zeros between", map[Severity]int{
			SeverityCritical: 1, SeverityMedium: 4,
		}, "1 critical, 4 medium"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatSeverityCounts(tt.counts); got != tt.want {
				t.Errorf("FormatSeverityCounts = %q, want %q", got, tt.want)
			}
		})
	}
}

// SeverityOrder must be the source the priority rank derives from — a drift
// between the two would reorder findings differently from how they are
// summarised.
func TestSeverityOrderDrivesPriorityRank(t *testing.T) {
	if len(SeverityOrder) != 5 {
		t.Fatalf("SeverityOrder has %d entries, want 5", len(SeverityOrder))
	}
	for i, s := range SeverityOrder {
		if severityPriorityRank[s] != i {
			t.Errorf("rank of %s = %d, want %d (must derive from SeverityOrder)", s, severityPriorityRank[s], i)
		}
	}
	if SeverityOrder[0] != SeverityCritical || SeverityOrder[4] != SeverityInfo {
		t.Errorf("SeverityOrder must run critical..info, got %v", SeverityOrder)
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(SeverityCritical) != 0 || SeverityRank(SeverityInfo) != 4 {
		t.Errorf("ranks: critical=%d info=%d, want 0 and 4", SeverityRank(SeverityCritical), SeverityRank(SeverityInfo))
	}
	// An unrecognised severity ranks past info so it sorts last, never tying.
	if SeverityRank(Severity("bogus")) != len(SeverityOrder) {
		t.Errorf("unknown severity rank = %d, want %d", SeverityRank(Severity("bogus")), len(SeverityOrder))
	}
	// Rank must agree with SeverityOrder for every level.
	for i, s := range SeverityOrder {
		if SeverityRank(s) != i {
			t.Errorf("SeverityRank(%s) = %d, want %d", s, SeverityRank(s), i)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	ff := []Finding{
		{Severity: SeverityHigh}, {Severity: SeverityHigh}, {Severity: SeverityCritical},
	}
	c := CountBySeverity(ff)
	if c[SeverityHigh] != 2 || c[SeverityCritical] != 1 {
		t.Errorf("CountBySeverity = %v", c)
	}
	if len(CountBySeverity(nil)) != 0 {
		t.Error("CountBySeverity(nil) should be empty")
	}
}

func TestSeverityLadder(t *testing.T) {
	// Downgraded and Upgraded are inverses, with the ends idempotent.
	down := map[Severity]Severity{
		SeverityCritical: SeverityHigh, SeverityHigh: SeverityMedium,
		SeverityMedium: SeverityLow, SeverityLow: SeverityInfo, SeverityInfo: SeverityInfo,
	}
	for s, want := range down {
		if got := s.Downgraded(); got != want {
			t.Errorf("%s.Downgraded() = %s, want %s", s, got, want)
		}
	}
	up := map[Severity]Severity{
		SeverityInfo: SeverityLow, SeverityLow: SeverityMedium,
		SeverityMedium: SeverityHigh, SeverityHigh: SeverityCritical, SeverityCritical: SeverityCritical,
	}
	for s, want := range up {
		if got := s.Upgraded(); got != want {
			t.Errorf("%s.Upgraded() = %s, want %s", s, got, want)
		}
	}
	// An unrecognized severity is unchanged either way.
	if Severity("weird").Upgraded() != "weird" || Severity("weird").Downgraded() != "weird" {
		t.Error("unknown severity must pass through the ladder unchanged")
	}
}
