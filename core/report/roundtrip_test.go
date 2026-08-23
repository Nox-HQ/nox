// Artifact round-trip contract tests.
//
// Every artifact nox writes is written for something else to read: findings.json
// for `nox fix`, `nox show`, `nox vex`, and any CI job; results.sarif for GitHub
// Code Scanning; the SBOMs for supply-chain tooling; the HTML report for a human.
// The unit tests around each reporter check the writer in isolation, which is
// exactly the blind spot that let `nox vex init` ship reading a JSON ARRAY out of
// a file the scanner writes as a JSON OBJECT: both sides were tested, the seam
// between them was not, and the command was broken against every real artifact.
//
// These tests cross that seam. Each one builds a realistic input, writes the
// artifact with the real writer, and reads it back with the real reader (or a
// strict parse into the format's own types), so a change to either side that
// breaks the other fails here rather than in a user's pipeline.
//
// The file lives in an external test package (report_test rather than report)
// deliberately: core/report/html, core/report/sbom, and core/detail all import
// core/report, so an in-package test could not reach them without an import
// cycle. Externally, the whole artifact surface is testable from one place.
package report_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
	htmlreport "github.com/nox-hq/nox/core/report/html"
	"github.com/nox-hq/nox/core/report/sarif"
	"github.com/nox-hq/nox/core/report/sbom"
)

const (
	roundTripVersion = "1.29.1"

	// A fixed SOURCE_DATE_EPOCH pins every artifact's timestamp so a
	// byte-comparison tests the reporter rather than the clock.
	roundTripEpoch = "1700000000"
	roundTripTime  = "2023-11-14T22:13:20Z"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// realisticFindingSet builds the shape a real scan produces: several rules,
// several severities, metadata on some findings, and two findings that a
// baseline and an inline suppression have taken out of the active set. A
// fixture of only active, metadata-free findings would pass round-trip tests
// while the fields that actually decide what a user sees were being dropped.
func realisticFindingSet() *findings.FindingSet {
	fs := findings.NewFindingSet()

	fs.Add(findings.Finding{
		RuleID:     "SEC001",
		Severity:   findings.SeverityCritical,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: "cmd/server/main.go", StartLine: 42, EndLine: 42, StartColumn: 9, EndColumn: 48},
		Message:    "hardcoded AWS access key in server bootstrap",
		Metadata:   map[string]string{"vuln_class": "secret", "reachability": "reachable"},
		Status:     findings.StatusNew,
	})
	fs.Add(findings.Finding{
		RuleID:     "VULN-GO-2024-1234",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: "go.mod", StartLine: 12, EndLine: 12},
		Message:    "golang.org/x/net 0.17.0 is affected by GHSA-4374-p667-p6c8",
		Metadata:   map[string]string{"vuln_class": "dependency", "fixed_in": "0.23.0"},
		Status:     findings.StatusNew,
	})
	fs.Add(findings.Finding{
		RuleID:     "AI-006",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceLow,
		Location:   findings.Location{FilePath: "internal/agent/prompt.go", StartLine: 88, EndLine: 91},
		Message:    "prompt content is written to the application log",
		Status:     findings.StatusNew,
	})
	fs.Add(findings.Finding{
		RuleID:     "IAC-002",
		Severity:   findings.SeverityLow,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: "infra/main.tf", StartLine: 5, EndLine: 5},
		Message:    "S3 bucket has no server-side encryption configured",
		Status:     findings.StatusBaselined,
	})
	fs.Add(findings.Finding{
		RuleID:     "SEC012",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: "testdata/fixtures/sample.py", StartLine: 3, EndLine: 3},
		Message:    "private key material in a test fixture",
		Status:     findings.StatusSuppressed,
	})

	return fs
}

// realisticInventory mirrors what the dependency analyzer hands the SBOM
// reporters: packages across ecosystems, a declared license, and a vulnerability
// attached to one of them.
func realisticInventory() *deps.PackageInventory {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "golang.org/x/net", Version: "0.17.0", Ecosystem: "go", License: "BSD-3-Clause"})
	inv.Add(deps.Package{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "requests", Version: "2.31.0", Ecosystem: "pypi", License: "Apache-2.0"})
	inv.SetVulnerabilities(0, []deps.Vulnerability{{
		ID:       "GHSA-4374-p667-p6c8",
		Summary:  "HTTP/2 rapid reset",
		Severity: findings.SeverityHigh,
	}})
	return inv
}

// sharedAdvisoryInventory puts ONE advisory on SEVERAL packages, which is the
// only shape that exercises the CycloneDX vulnerability tie-breaker. Those
// entries are collected by ranging a Go map, so equal vuln IDs have to be
// ordered by something else or the artifact's bytes change run to run.
func sharedAdvisoryInventory() *deps.PackageInventory {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "acorn", Version: "8.11.0", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "browserify", Version: "17.0.0", Ecosystem: "npm", License: "MIT"})
	inv.Add(deps.Package{Name: "webpack", Version: "5.89.0", Ecosystem: "npm", License: "MIT"})
	shared := []deps.Vulnerability{{
		ID:       "CVE-2024-0001",
		Summary:  "shared transitive advisory",
		Severity: findings.SeverityMedium,
	}}
	for i := 0; i < 3; i++ {
		inv.SetVulnerabilities(i, shared)
	}
	return inv
}

// configuredJSONReporter returns the reporter with every optional channel
// populated. Meta.Offline, the SAST profile, and the degradation list are the
// fields a reviewer reads to decide whether to trust the report at all, so they
// must survive the write just as findings do.
func configuredJSONReporter() *report.JSONReporter {
	r := report.NewJSONReporter(roundTripVersion)
	r.Offline = true
	r.SASTLanguages = map[string]string{"go": "deep", "python": "standard", "rust": "off"}
	r.Degradations = []report.Degradation{{
		Kind:   "osv_lookup",
		Detail: "osv.dev unreachable",
		Impact: "known-vulnerability findings may be missing",
	}}
	return r
}

func findingByRule(t *testing.T, items []findings.Finding, ruleID string) findings.Finding {
	t.Helper()
	for i := range items {
		if items[i].RuleID == ruleID {
			return items[i]
		}
	}
	t.Fatalf("rule %q missing from artifact (findings present: %d)", ruleID, len(items))
	return findings.Finding{}
}

// ---------------------------------------------------------------------------
// findings.json — the pair that broke
// ---------------------------------------------------------------------------

func TestRoundTrip_FindingsJSON_ReadBackByRealReader(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	fs := realisticFindingSet()
	reporter := configuredJSONReporter()

	// Enrichments are keyed by fingerprint, and the fingerprint is computed at
	// Add time. Linking through the real value is the point: an enrichment whose
	// key does not survive the write is an enrichment no consumer can attach.
	sec001 := findingByRule(t, fs.Findings(), "SEC001")
	reporter.Enrichments = []findings.Enrichment{{
		FindingFingerprint: sec001.Fingerprint,
		Kind:               "triage",
		Title:              "Confirmed live credential",
		Body:               "Key responded to a **sts:GetCallerIdentity** probe.",
		Metadata:           map[string]string{"probe": "sts"},
		Confidence:         findings.ConfidenceHigh,
		Source:             "exploit-validation",
	}}

	path := filepath.Join(t.TempDir(), "findings.json")
	if err := reporter.WriteToFile(fs, path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}

	var rep report.JSONReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("artifact is not parseable as report.JSONReport: %v", err)
	}

	if rep.Meta.SchemaVersion != "1.0.0" {
		t.Errorf("Meta.SchemaVersion = %q, want 1.0.0", rep.Meta.SchemaVersion)
	}
	if rep.Meta.ToolName != "nox" || rep.Meta.ToolVersion != roundTripVersion {
		t.Errorf("Meta tool identity = %q/%q, want nox/%s", rep.Meta.ToolName, rep.Meta.ToolVersion, roundTripVersion)
	}
	if rep.Meta.GeneratedAt != roundTripTime {
		t.Errorf("Meta.GeneratedAt = %q, want %q — SOURCE_DATE_EPOCH is not reaching the artifact", rep.Meta.GeneratedAt, roundTripTime)
	}
	// The offline attestation is a claim a reviewer relies on; losing it in
	// serialization turns "scanned with no network" into "unknown".
	if !rep.Meta.Offline {
		t.Error("Meta.Offline = false, want true — the proof-of-offline attestation did not survive the write")
	}
	if rep.Meta.SASTLanguages["rust"] != "off" {
		t.Errorf("Meta.SASTLanguages[rust] = %q, want off", rep.Meta.SASTLanguages["rust"])
	}
	// A degradation that does not reach the artifact makes an empty findings
	// list indistinguishable from a scan that never looked.
	if len(rep.Meta.Degradations) != 1 || rep.Meta.Degradations[0].Kind != "osv_lookup" {
		t.Fatalf("Meta.Degradations = %+v, want the single osv_lookup entry", rep.Meta.Degradations)
	}
	if rep.Meta.Degradations[0].Impact == "" {
		t.Error("Degradation.Impact is empty — the field that answers 'should I trust this report?' was dropped")
	}

	// findings.json carries suppressed and baselined findings too: it is the
	// audit record, not the alert list. Dropping them here would silently make
	// `nox diff` and baseline tooling unable to see what was waived.
	if len(rep.Findings) != 5 {
		t.Fatalf("got %d findings in artifact, want all 5 including non-active", len(rep.Findings))
	}

	got := findingByRule(t, rep.Findings, "SEC001")
	if got.Message != sec001.Message {
		t.Errorf("Message = %q, want %q", got.Message, sec001.Message)
	}
	if got.Location.FilePath != "cmd/server/main.go" || got.Location.StartLine != 42 || got.Location.EndColumn != 48 {
		t.Errorf("Location = %+v, want cmd/server/main.go:42 with columns intact", got.Location)
	}
	if got.Severity != findings.SeverityCritical || got.Confidence != findings.ConfidenceHigh {
		t.Errorf("severity/confidence = %q/%q, want critical/high", got.Severity, got.Confidence)
	}
	if got.Fingerprint != sec001.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q — a changed fingerprint un-waives every baseline entry", got.Fingerprint, sec001.Fingerprint)
	}
	if got.ID != sec001.ID {
		t.Errorf("ID = %q, want %q", got.ID, sec001.ID)
	}
	if got.Metadata["reachability"] != "reachable" {
		t.Errorf("Metadata[reachability] = %q, want reachable", got.Metadata["reachability"])
	}

	// A post-scan plugin that annotates rather than detects is a no-op to every
	// consumer if its enrichments do not reach the artifact keyed to a finding
	// that is actually in it.
	if len(rep.Enrichments) != 1 {
		t.Fatalf("got %d enrichments, want 1", len(rep.Enrichments))
	}
	enr := rep.Enrichments[0]
	if enr.FindingFingerprint != sec001.Fingerprint {
		t.Errorf("enrichment fingerprint = %q, want %q", enr.FindingFingerprint, sec001.Fingerprint)
	}
	if enr.Body == "" || enr.Source != "exploit-validation" || enr.Confidence != findings.ConfidenceHigh {
		t.Errorf("enrichment fields lost in round trip: %+v", enr)
	}
	var linked bool
	for i := range rep.Findings {
		if rep.Findings[i].Fingerprint == enr.FindingFingerprint {
			linked = true
		}
	}
	if !linked {
		t.Error("enrichment references a fingerprint that is not in the artifact — the link is dangling")
	}

	// core/detail is a real consumer of this file (it backs `nox show`). Reading
	// through it, rather than only through the writer's own type, is what proves
	// the seam works end to end.
	store, err := detail.LoadFromFile(path)
	if err != nil {
		t.Fatalf("detail.LoadFromFile on a freshly written artifact: %v", err)
	}
	if store.Count() != 5 {
		t.Errorf("store.Count() = %d, want 5", store.Count())
	}
	if _, ok := store.ByID(sec001.ID); !ok {
		t.Errorf("store.ByID(%q) missed — the identity a user pastes from one command into another does not resolve", sec001.ID)
	}
}

// TestRoundTrip_FindingsJSONIsAnObject pins the top-level shape of findings.json.
//
// This is the exact contract `nox vex init` violated: it unmarshalled the file
// into a []findings.Finding while the scanner writes {meta, findings,
// enrichments}. Any reader that guesses the shape rather than using
// report.JSONReport is broken against every real artifact, so the shape is
// asserted here as a contract in its own right.
func TestRoundTrip_FindingsJSONIsAnObject(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	data, err := configuredJSONReporter().Generate(realisticFindingSet())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("findings.json top level is not a JSON object: %v", err)
	}
	for _, key := range []string{"meta", "findings"} {
		if _, ok := top[key]; !ok {
			t.Errorf("findings.json is missing the %q key; keys present: %v", key, mapKeys(top))
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(string(top["findings"])), "[") {
		t.Error(`the "findings" value is not a JSON array`)
	}

	// The negative half of the contract: a reader expecting a bare array must
	// fail loudly on a real artifact. If this ever starts succeeding the
	// top-level shape has changed and every reader of the object form breaks.
	var bare []findings.Finding
	if err := json.Unmarshal(data, &bare); err == nil {
		t.Error("findings.json decoded into a bare []findings.Finding — the documented object shape has changed; update every reader")
	}
}

// `nox vex init` reads findings.json and builds a VEX stub from it. It once
// decoded the file into a []findings.Finding, but `nox scan` writes the JSON
// OBJECT asserted in TestRoundTrip_FindingsJSONIsAnObject, so the command failed
// on every artifact nox produces — and no test caught it, because nothing
// crossed the writer to reader seam.
//
// It now goes through report.LoadFindingsFile, the one shared loader. This
// exercises that exact path against a real generated artifact, so a future
// change that reintroduces a bespoke decode fails here.
func TestRoundTrip_VexInitReadsScanOutput(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if err := configuredJSONReporter().WriteToFile(realisticFindingSet(), path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	// The loader `nox vex init` actually uses.
	items, err := report.LoadFindingsFile(path)
	if err != nil {
		t.Fatalf("nox vex init cannot read the artifact nox scan writes: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("nox vex init would build a VEX stub with no statements")
	}
}

// ---------------------------------------------------------------------------
// Status — the rule that decides what a user sees
// ---------------------------------------------------------------------------

// TestRoundTrip_StatusSurvives checks that a waived finding stays waived across
// the write. A baselined finding that came back as active would re-open every
// accepted finding on the next scan and turn a green gate red; one that came
// back active in SARIF would do it inside GitHub Code Scanning, where nobody is
// looking at the JSON to notice.
func TestRoundTrip_StatusSurvives(t *testing.T) {
	statuses := []findings.Status{
		findings.StatusNew,
		findings.StatusBaselined,
		findings.StatusSuppressed,
		findings.StatusVEXNotAffected,
		findings.StatusVEXUnderInvestigation,
		findings.StatusVEXFixed,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

			fs := findings.NewFindingSet()
			fs.Add(findings.Finding{
				RuleID:     "SEC001",
				Severity:   findings.SeverityCritical,
				Confidence: findings.ConfidenceHigh,
				Location:   findings.Location{FilePath: "cmd/server/main.go", StartLine: 42},
				Message:    "hardcoded AWS access key in server bootstrap",
				Status:     status,
			})

			path := filepath.Join(t.TempDir(), "findings.json")
			if err := report.NewJSONReporter(roundTripVersion).WriteToFile(fs, path); err != nil {
				t.Fatalf("WriteToFile: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading artifact: %v", err)
			}

			var rep report.JSONReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatalf("parsing artifact: %v", err)
			}
			if len(rep.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(rep.Findings))
			}
			if rep.Findings[0].Status != status {
				t.Fatalf("Status = %q, want %q", rep.Findings[0].Status, status)
			}

			// The reader must reach the same active/waived verdict the writer
			// held. Rebuilding a set from the parsed findings is what every
			// consumer effectively does before filtering.
			reloaded := findings.NewFindingSet()
			for i := range rep.Findings {
				reloaded.Add(rep.Findings[i])
			}
			wantActive := 0
			if status.IsActive() {
				wantActive = 1
			}
			if n := len(reloaded.ActiveFindings()); n != wantActive {
				t.Errorf("ActiveFindings() = %d after round trip, want %d for status %q", n, wantActive, status)
			}

			// core/detail's default filter is the same rule seen through a real
			// reader.
			store, err := detail.LoadFromFile(path)
			if err != nil {
				t.Fatalf("detail.LoadFromFile: %v", err)
			}
			if n := len(store.Filter(detail.Filter{})); n != wantActive {
				t.Errorf("detail default filter surfaced %d findings, want %d for status %q", n, wantActive, status)
			}
			if n := len(store.Filter(detail.Filter{IncludeSuppressed: true})); n != 1 {
				t.Errorf("detail filter with IncludeSuppressed surfaced %d findings, want 1 — the audit trail is gone", n)
			}

			// SARIF and HTML publish only the active set, so a waived finding
			// must not appear in either.
			sarifData, err := sarif.NewReporter(roundTripVersion, nil).Generate(fs)
			if err != nil {
				t.Fatalf("sarif Generate: %v", err)
			}
			var sr sarif.Report
			if err := json.Unmarshal(sarifData, &sr); err != nil {
				t.Fatalf("parsing SARIF: %v", err)
			}
			if len(sr.Runs) != 1 {
				t.Fatalf("SARIF runs = %d, want 1", len(sr.Runs))
			}
			if len(sr.Runs[0].Results) != wantActive {
				t.Errorf("SARIF results = %d, want %d for status %q", len(sr.Runs[0].Results), wantActive, status)
			}

			htmlData, err := htmlreport.NewReporter(roundTripVersion).Generate(fs)
			if err != nil {
				t.Fatalf("html Generate: %v", err)
			}
			inHTML := strings.Contains(string(htmlData), "hardcoded AWS access key")
			if inHTML != status.IsActive() {
				t.Errorf("HTML report contains the finding = %v, want %v for status %q", inHTML, status.IsActive(), status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// results.sarif
// ---------------------------------------------------------------------------

// TestRoundTrip_SARIFStructure parses the emitted SARIF back and checks the
// properties GitHub Code Scanning validates on upload. GitHub rejects the whole
// submission — not the offending result — for a dangling ruleIndex or an empty
// artifact URI, so a single malformed result silently costs a repository its
// entire scan while the run looks clean locally.
func TestRoundTrip_SARIFStructure(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	fs := realisticFindingSet()
	data, err := sarif.NewReporter(roundTripVersion, nil).Generate(fs)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := sarif.NewReporter(roundTripVersion, nil).WriteToFile(realisticFindingSet(), path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	fromDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	if !bytes.Equal(fromDisk, data) {
		t.Error("WriteToFile and Generate disagree — the file on disk is not the document the reporter produced")
	}

	var rep sarif.Report
	dec := json.NewDecoder(bytes.NewReader(fromDisk))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("emitted SARIF does not parse strictly into its own types: %v", err)
	}

	if rep.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", rep.Version)
	}
	if !strings.Contains(rep.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("$schema = %q, want the SARIF 2.1.0 schema URI", rep.Schema)
	}
	if len(rep.Runs) != 1 {
		t.Fatalf("runs = %d, want exactly 1", len(rep.Runs))
	}

	driver := rep.Runs[0].Tool.Driver
	if driver.Name != "nox" || driver.Version != roundTripVersion || driver.InformationURI == "" {
		t.Errorf("tool.driver = %+v, want nox/%s with an informationUri", driver, roundTripVersion)
	}

	// Only the active findings are published.
	if len(rep.Runs[0].Results) != 3 {
		t.Fatalf("results = %d, want 3 active findings", len(rep.Runs[0].Results))
	}

	for i, res := range rep.Runs[0].Results {
		if res.RuleID == "" {
			t.Errorf("results[%d] has no ruleId", i)
			continue
		}
		if res.RuleIndex < 0 || res.RuleIndex >= len(driver.Rules) {
			t.Errorf("results[%d] ruleIndex %d is outside the rule catalog (%d entries) — GitHub rejects the whole upload for this", i, res.RuleIndex, len(driver.Rules))
			continue
		}
		if got := driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("results[%d] ruleId %q points at catalog entry %q", i, res.RuleID, got)
		}
		if res.Level == "" {
			t.Errorf("results[%d] has no level", i)
		}
		if res.Message.Text == "" {
			t.Errorf("results[%d] has an empty message", i)
		}
		if res.Fingerprints["nox/v1"] == "" {
			t.Errorf("results[%d] lost its nox/v1 fingerprint — Code Scanning cannot track the alert across scans", i)
		}
		if len(res.Locations) != 1 {
			t.Errorf("results[%d] has %d locations, want 1 (every fixture finding has a file)", i, len(res.Locations))
			continue
		}
		phys := res.Locations[0].PhysicalLocation
		if phys.ArtifactLocation.URI == "" {
			t.Errorf("results[%d] has an empty artifact URI — GitHub fails the submission with 'expected artifact location'", i)
		}
		if phys.Region == nil || phys.Region.StartLine <= 0 {
			t.Errorf("results[%d] lost its region; the alert would be reported against the whole file", i)
		}
	}

	// The reachability class and the severity-downgrade audit trail travel in
	// the property bag; without it a downgraded finding shows only its final
	// severity with no record of the override.
	var sawProps bool
	for _, res := range rep.Runs[0].Results {
		if res.RuleID == "SEC001" {
			sawProps = res.Properties["reachability"] == "reachable"
		}
	}
	if !sawProps {
		t.Error("SEC001 metadata did not reach the SARIF property bag")
	}
}

// ---------------------------------------------------------------------------
// SBOMs
// ---------------------------------------------------------------------------

func TestRoundTrip_CycloneDXStructure(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := sbom.NewCycloneDXReporter(roundTripVersion).WriteToFile(realisticInventory(), path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}

	var doc sbom.CDXReport
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("emitted CycloneDX does not parse: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion == "" {
		t.Errorf("bomFormat/specVersion = %q/%q — consumers dispatch on these before reading anything else", doc.BOMFormat, doc.SpecVersion)
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want a urn:uuid", doc.SerialNumber)
	}
	if doc.Metadata.Timestamp != roundTripTime {
		t.Errorf("metadata.timestamp = %q, want %q from SOURCE_DATE_EPOCH", doc.Metadata.Timestamp, roundTripTime)
	}
	if len(doc.Metadata.Tools) != 1 || doc.Metadata.Tools[0].Version != roundTripVersion {
		t.Errorf("metadata.tools = %+v, want one nox entry at %s", doc.Metadata.Tools, roundTripVersion)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("components = %d, want 3", len(doc.Components))
	}
	for i, c := range doc.Components {
		if c.Name == "" || c.Version == "" || c.PURL == "" || c.BOMRef == "" {
			t.Errorf("components[%d] = %+v — an incomplete component is unusable to a supply-chain consumer", i, c)
		}
	}

	// The vulnerability must still point at a component that exists in this
	// document; a dangling bom-ref makes the advisory unattributable.
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(doc.Vulnerabilities))
	}
	vuln := doc.Vulnerabilities[0]
	if vuln.ID != "GHSA-4374-p667-p6c8" {
		t.Errorf("vulnerability id = %q", vuln.ID)
	}
	if len(vuln.Affects) != 1 {
		t.Fatalf("vulnerability affects = %d, want 1", len(vuln.Affects))
	}
	var resolved bool
	for _, c := range doc.Components {
		if c.BOMRef == vuln.Affects[0].Ref {
			resolved = true
			if c.Name != "golang.org/x/net" {
				t.Errorf("advisory attached to %q, want golang.org/x/net", c.Name)
			}
		}
	}
	if !resolved {
		t.Errorf("vulnerability affects bom-ref %q, which no component declares", vuln.Affects[0].Ref)
	}
}

func TestRoundTrip_SPDXStructure(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	path := filepath.Join(t.TempDir(), "sbom.spdx.json")
	if err := sbom.NewSPDXReporter(roundTripVersion).WriteToFile(realisticInventory(), path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}

	var doc sbom.SPDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("emitted SPDX does not parse: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.DataLicense == "" || doc.DocumentNamespace == "" || doc.Name == "" {
		t.Errorf("document header incomplete: %+v", doc)
	}
	if doc.CreationInfo.Created != roundTripTime {
		t.Errorf("creationInfo.created = %q, want %q from SOURCE_DATE_EPOCH", doc.CreationInfo.Created, roundTripTime)
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(doc.Packages))
	}

	ids := make(map[string]bool, len(doc.Packages))
	for i, p := range doc.Packages {
		if p.SPDXID == "" || p.Name == "" || p.VersionInfo == "" {
			t.Errorf("packages[%d] = %+v is missing required identity fields", i, p)
		}
		// SPDX 2.3 rejects free text here; NOASSERTION is the legal fallback and
		// an empty string is not.
		if p.DeclaredLicense == "" {
			t.Errorf("packages[%d] has an empty licenseDeclared, which is spec-invalid (want NOASSERTION at worst)", i)
		}
		if p.DownloadLocation == "" {
			t.Errorf("packages[%d] has an empty downloadLocation, which is spec-invalid", i)
		}
		ids[p.SPDXID] = true
	}

	// Every relationship must resolve inside the document, or the package graph
	// is broken for anything that walks it.
	if len(doc.Relationships) != 3 {
		t.Fatalf("relationships = %d, want one DESCRIBES per package", len(doc.Relationships))
	}
	for i, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" {
			t.Errorf("relationships[%d] is rooted at %q, want SPDXRef-DOCUMENT", i, rel.SPDXElementID)
		}
		if !ids[rel.RelatedSPDXElement] {
			t.Errorf("relationships[%d] points at %q, which no package declares", i, rel.RelatedSPDXElement)
		}
	}

	// The advisory travels as a SECURITY external ref; losing it drops the only
	// vulnerability signal SPDX carries.
	var sawAdvisory bool
	for _, p := range doc.Packages {
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceCategory == "SECURITY" && strings.Contains(ref.ReferenceLocator, "GHSA-4374-p667-p6c8") {
				sawAdvisory = true
			}
		}
	}
	if !sawAdvisory {
		t.Error("the GHSA advisory did not survive as a SECURITY external ref")
	}
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

// TestRoundTrip_HTMLInjectsData guards against the report rendering as a shell:
// a template that executes but binds nothing still produces a plausible-looking
// page, and nobody notices until an operator reads a clean-looking report of a
// dirty repository.
func TestRoundTrip_HTMLInjectsData(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	path := filepath.Join(t.TempDir(), "report.html")
	if err := htmlreport.NewReporter(roundTripVersion).WriteToFile(realisticFindingSet(), path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	out := string(raw)

	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Error("HTML report does not start with a doctype")
	}
	if strings.Contains(out, "{{") || strings.Contains(out, "}}") {
		t.Error("HTML report contains an unexecuted template action — data was not injected")
	}

	for _, want := range []string{
		"SEC001",
		"hardcoded AWS access key in server bootstrap",
		"cmd/server/main.go",
		"VULN-GO-2024-1234",
		"internal/agent/prompt.go",
		roundTripVersion,
		roundTripTime,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report is missing %q", want)
		}
	}

	// Waived findings are not published, and the counters must agree with the
	// rows: a report claiming five findings while showing three is worse than
	// one that shows neither.
	for _, unwanted := range []string{"IAC-002", "S3 bucket has no server-side encryption", "SEC012"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("HTML report published waived content %q", unwanted)
		}
	}
	if !strings.Contains(out, `<div class="count">3</div>`) {
		t.Error("HTML report's total counter does not read 3 active findings")
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestRoundTrip_Determinism generates each artifact twice from equivalent
// freshly-built inputs and requires byte-identical output. Nox promises the same
// inputs produce the same outputs; a reporter that ranges a Go map without
// sorting satisfies every content assertion above and still breaks that promise,
// producing spurious diffs in committed artifacts and defeating CI caches.
//
// Building the input twice, rather than reusing one set, is deliberate: it gives
// map iteration order a second chance to differ.
func TestRoundTrip_Determinism(t *testing.T) {
	tests := []struct {
		name string
		gen  func() ([]byte, error)
	}{
		{"findings.json", func() ([]byte, error) {
			r := configuredJSONReporter()
			fs := realisticFindingSet()
			r.Enrichments = []findings.Enrichment{{
				FindingFingerprint: findingByRule(t, fs.Findings(), "SEC001").Fingerprint,
				Kind:               "triage",
				Title:              "Confirmed live credential",
				Metadata:           map[string]string{"probe": "sts", "region": "eu-central-1"},
			}}
			return r.Generate(fs)
		}},
		{"findings.json prioritized", func() ([]byte, error) {
			r := configuredJSONReporter()
			r.Prioritize = true
			return r.Generate(realisticFindingSet())
		}},
		{"results.sarif", func() ([]byte, error) {
			return sarif.NewReporter(roundTripVersion, nil).Generate(realisticFindingSet())
		}},
		{"sbom.cdx.json", func() ([]byte, error) {
			return sbom.NewCycloneDXReporter(roundTripVersion).Generate(realisticInventory())
		}},
		{"sbom.cdx.json shared advisory", func() ([]byte, error) {
			return sbom.NewCycloneDXReporter(roundTripVersion).Generate(sharedAdvisoryInventory())
		}},
		{"sbom.spdx.json", func() ([]byte, error) {
			return sbom.NewSPDXReporter(roundTripVersion).Generate(realisticInventory())
		}},
		{"report.html", func() ([]byte, error) {
			return htmlreport.NewReporter(roundTripVersion).Generate(realisticFindingSet())
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

			first, err := tc.gen()
			if err != nil {
				t.Fatalf("first generate: %v", err)
			}
			second, err := tc.gen()
			if err != nil {
				t.Fatalf("second generate: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("%s is not byte-identical across runs of the same input (%d vs %d bytes)", tc.name, len(first), len(second))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Empty input
// ---------------------------------------------------------------------------

// TestRoundTrip_EmptyInputStillValid covers the clean scan: no findings, no
// packages. Every artifact must still be a valid, parseable document of its
// format. A clean scan that emits zero bytes or a null-filled document breaks
// the pipeline of exactly the users who have nothing wrong with their code —
// the failure they are least equipped to diagnose.
func TestRoundTrip_EmptyInputStillValid(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		gen      func() ([]byte, error)
		validate func(t *testing.T, data []byte)
	}{
		{
			name:     "findings.json",
			filename: "findings.json",
			gen: func() ([]byte, error) {
				return report.NewJSONReporter(roundTripVersion).Generate(findings.NewFindingSet())
			},
			validate: func(t *testing.T, data []byte) {
				t.Helper()
				var rep report.JSONReport
				if err := json.Unmarshal(data, &rep); err != nil {
					t.Fatalf("parse: %v", err)
				}
				if rep.Meta.SchemaVersion == "" {
					t.Error("empty scan produced a report with no schema version")
				}
				if rep.Findings == nil {
					t.Error("findings is null, not [] — a consumer ranging it without a nil check panics")
				}
				// The null check above is on the decoded value; assert the wire
				// form too, since that is what non-Go consumers read.
				if strings.Contains(string(data), `"findings": null`) {
					t.Error(`the artifact literally contains "findings": null`)
				}
			},
		},
		{
			name:     "results.sarif",
			filename: "results.sarif",
			gen: func() ([]byte, error) {
				return sarif.NewReporter(roundTripVersion, nil).Generate(findings.NewFindingSet())
			},
			validate: func(t *testing.T, data []byte) {
				t.Helper()
				var rep sarif.Report
				if err := json.Unmarshal(data, &rep); err != nil {
					t.Fatalf("parse: %v", err)
				}
				if rep.Version != "2.1.0" || len(rep.Runs) != 1 {
					t.Fatalf("a clean scan must still be a one-run SARIF 2.1.0 document, got version %q with %d runs", rep.Version, len(rep.Runs))
				}
				if rep.Runs[0].Tool.Driver.Name != "nox" {
					t.Error("the tool driver is missing from a clean-scan SARIF")
				}
				if rep.Runs[0].Results == nil {
					t.Error("results is null, not [] — GitHub Code Scanning would reject the upload")
				}
			},
		},
		{
			name:     "sbom.cdx.json",
			filename: "sbom.cdx.json",
			gen: func() ([]byte, error) {
				return sbom.NewCycloneDXReporter(roundTripVersion).Generate(&deps.PackageInventory{})
			},
			validate: func(t *testing.T, data []byte) {
				t.Helper()
				var doc sbom.CDXReport
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatalf("parse: %v", err)
				}
				if doc.BOMFormat != "CycloneDX" || doc.SpecVersion == "" {
					t.Error("a dependency-free project must still get a well-formed CycloneDX header")
				}
				if doc.Components == nil {
					t.Error("components is null, not [] — CycloneDX consumers require an array")
				}
			},
		},
		{
			name:     "sbom.spdx.json",
			filename: "sbom.spdx.json",
			gen: func() ([]byte, error) {
				return sbom.NewSPDXReporter(roundTripVersion).Generate(&deps.PackageInventory{})
			},
			validate: func(t *testing.T, data []byte) {
				t.Helper()
				var doc sbom.SPDXDocument
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatalf("parse: %v", err)
				}
				if doc.SPDXVersion != "SPDX-2.3" || doc.SPDXID != "SPDXRef-DOCUMENT" {
					t.Error("a dependency-free project must still get a well-formed SPDX header")
				}
				if doc.Packages == nil {
					t.Error("packages is null, not [] — SPDX consumers require an array")
				}
			},
		},
		{
			name:     "report.html",
			filename: "report.html",
			gen: func() ([]byte, error) {
				return htmlreport.NewReporter(roundTripVersion).Generate(findings.NewFindingSet())
			},
			validate: func(t *testing.T, data []byte) {
				t.Helper()
				out := string(data)
				if !strings.HasPrefix(out, "<!DOCTYPE html>") {
					t.Error("clean-scan HTML report is not a document")
				}
				if strings.Contains(out, "{{") {
					t.Error("clean-scan HTML report contains an unexecuted template action")
				}
				if !strings.Contains(out, "No security findings detected.") {
					t.Error("clean-scan HTML report does not say the scan was clean")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

			data, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("a clean scan produced an empty artifact")
			}

			// Go through disk as well: the artifact a user's pipeline reads is
			// the file, not the byte slice.
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatalf("writing artifact: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading artifact: %v", err)
			}
			tc.validate(t, raw)
		})
	}
}

// ---------------------------------------------------------------------------
// Unicode and special characters
// ---------------------------------------------------------------------------

// TestRoundTrip_UnicodeSurvives pushes non-ASCII text, quotes, and a newline
// through every artifact. Escaping bugs here are silent: the file still parses,
// so the only symptom is a message or a path that quietly comes back wrong — and
// a wrong path in SARIF means the alert lands on the wrong file, or nowhere.
func TestRoundTrip_UnicodeSurvives(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", roundTripEpoch)

	const (
		unicodePath    = "src/配置/naïve dir/файл.go"
		unicodeMessage = "clé API « codée en dur » — 秘密鍵 🔑 in\ttab and \"quoted\" text"
	)

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		RuleID:     "SEC001",
		Severity:   findings.SeverityCritical,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{FilePath: unicodePath, StartLine: 7},
		Message:    unicodeMessage,
		Metadata:   map[string]string{"note": "ключ 🔑"},
	})

	t.Run("findings.json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "findings.json")
		if err := report.NewJSONReporter(roundTripVersion).WriteToFile(fs, path); err != nil {
			t.Fatalf("WriteToFile: %v", err)
		}
		store, err := detail.LoadFromFile(path)
		if err != nil {
			t.Fatalf("detail.LoadFromFile: %v", err)
		}
		items := store.All()
		if len(items) != 1 {
			t.Fatalf("got %d findings, want 1", len(items))
		}
		if items[0].Message != unicodeMessage {
			t.Errorf("Message = %q, want %q", items[0].Message, unicodeMessage)
		}
		if items[0].Location.FilePath != unicodePath {
			t.Errorf("FilePath = %q, want %q", items[0].Location.FilePath, unicodePath)
		}
		if items[0].Metadata["note"] != "ключ 🔑" {
			t.Errorf("Metadata[note] = %q", items[0].Metadata["note"])
		}
	})

	t.Run("results.sarif", func(t *testing.T) {
		data, err := sarif.NewReporter(roundTripVersion, nil).Generate(fs)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		var rep sarif.Report
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(rep.Runs) != 1 || len(rep.Runs[0].Results) != 1 {
			t.Fatalf("want exactly one result, got runs=%d", len(rep.Runs))
		}
		res := rep.Runs[0].Results[0]
		if res.Message.Text != unicodeMessage {
			t.Errorf("SARIF message = %q, want %q", res.Message.Text, unicodeMessage)
		}
		if len(res.Locations) != 1 {
			t.Fatalf("want one location, got %d", len(res.Locations))
		}
		// SARIF artifact locations are URIs, so non-ASCII and spaces are
		// percent-encoded on the way out. That is correct — but it is only
		// correct if it decodes back to the exact path that was scanned.
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		decoded, err := url.PathUnescape(uri)
		if err != nil {
			t.Fatalf("SARIF artifact URI %q is not valid percent-encoding: %v", uri, err)
		}
		if decoded != unicodePath {
			t.Errorf("SARIF artifact URI decoded to %q, want %q — the alert would land on the wrong file", decoded, unicodePath)
		}
	})

	t.Run("report.html", func(t *testing.T) {
		data, err := htmlreport.NewReporter(roundTripVersion).Generate(fs)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		out := string(data)
		// html/template escapes the ASCII metacharacters but must leave the
		// non-ASCII text alone; a mojibake'd path is unusable to the human the
		// report is for.
		for _, want := range []string{"配置", "naïve dir", "файл.go", "秘密鍵 🔑", "clé API"} {
			if !strings.Contains(out, want) {
				t.Errorf("HTML report lost %q", want)
			}
		}
	})

	t.Run("sbom", func(t *testing.T) {
		inv := &deps.PackageInventory{}
		inv.Add(deps.Package{Name: "паке́т-ñame", Version: "1.0.0+ünïcode", Ecosystem: "npm", License: "MIT"})

		cdx, err := sbom.NewCycloneDXReporter(roundTripVersion).Generate(inv)
		if err != nil {
			t.Fatalf("cyclonedx Generate: %v", err)
		}
		var doc sbom.CDXReport
		if err := json.Unmarshal(cdx, &doc); err != nil {
			t.Fatalf("cyclonedx parse: %v", err)
		}
		if len(doc.Components) != 1 {
			t.Fatalf("components = %d, want 1", len(doc.Components))
		}
		if doc.Components[0].Name != "паке́т-ñame" || doc.Components[0].Version != "1.0.0+ünïcode" {
			t.Errorf("component identity corrupted: %+v", doc.Components[0])
		}

		spdx, err := sbom.NewSPDXReporter(roundTripVersion).Generate(inv)
		if err != nil {
			t.Fatalf("spdx Generate: %v", err)
		}
		var sdoc sbom.SPDXDocument
		if err := json.Unmarshal(spdx, &sdoc); err != nil {
			t.Fatalf("spdx parse: %v", err)
		}
		if len(sdoc.Packages) != 1 {
			t.Fatalf("packages = %d, want 1", len(sdoc.Packages))
		}
		if sdoc.Packages[0].Name != "паке́т-ñame" || sdoc.Packages[0].VersionInfo != "1.0.0+ünïcode" {
			t.Errorf("package identity corrupted: %+v", sdoc.Packages[0])
		}
	})
}

func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
