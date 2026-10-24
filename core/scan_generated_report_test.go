package core

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/replay"
	"github.com/nox-hq/nox/core/report/sbom"
)

// A report nox wrote is not source, wherever it sits.
//
// ScanOptions.OutputDir keeps a scan from reading the report it is about to
// overwrite. It cannot see the same report anywhere else, and that is the usual
// case: a CI artifact downloaded into the tree, an output directory renamed to
// keep the previous run, `reports/2026-10-01/`, a results.sarif committed so a
// reviewer can read it. Measured on v1.48.2 against a small Express app: 44
// findings, `cp -R out old-report`, then 48 — AI-009 ("LLM output passed to code
// execution function") and AI-038 twice each, all located in
// old-report/results.sarif, matching the rule descriptions nox itself wrote
// into the SARIF rule catalog. A findings-rich tree's --evidence-out file added
// 37 DATA-001 findings per copy the same way.
//
// So the decision is made on what the file says it is, not on where it is.

// writeEveryReport writes each report kind the CLI writes, with the CLI's own
// reporters, under dir with names that match none of the defaults.
func writeEveryReport(t *testing.T, res *ScanResult, dir string) []string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var written []string
	write := func(name string, fn func(string) error) {
		p := filepath.Join(dir, name)
		if err := fn(p); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		written = append(written, p)
	}
	write("scan.json", func(p string) error {
		return res.JSONReporter("test").WriteToFile(res.Findings, p)
	})
	write("scan.sarif", func(p string) error {
		r := res.SARIFReporter("test")
		// The CLI embeds the full rule catalog, and its prose is what fired.
		r.Rules = res.Rules
		return r.WriteToFile(res.Findings, p)
	})
	write("bom.cdx.json", func(p string) error {
		return sbom.NewCycloneDXReporter("test").WriteToFile(res.Inventory, p)
	})
	write("bom.spdx.json", func(p string) error {
		return sbom.NewSPDXReporter("test").WriteToFile(res.Inventory, p)
	})
	write("index.html", func(p string) error {
		return res.HTMLReporter("test").WriteToFile(res.Findings, p)
	})
	write("evidence.json", func(p string) error {
		return res.EvidenceArtifact(replay.Inputs{ToolName: "nox", ToolVersion: "test"}).WriteFile(p)
	})
	return written
}

// seededAWSKey returns an access key ID in the real format, from a fixed seed,
// so the true positive below is a credential-shaped value nobody typed.
func seededAWSKey() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	r := rand.New(rand.NewSource(20261024)) //nolint:gosec // deterministic fixture, not a secret
	b := make([]byte, 16)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return "AKIA" + string(b)
}

func TestAScanDoesNotReadAReportNoxWroteAnywhereInTheTree(t *testing.T) {
	dir := t.TempDir()
	src := "import openai\nmodel = \"gpt-3.5-turbo\"\nout = openai.chat(model=model)\neval(out)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("openai==0.27.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := ScanOptions{Offline: true, RecordReasoning: true}
	first, err := RunScanWithOptions(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	baseline := len(first.Findings.Findings())

	// Not the output directory, not the default names.
	written := writeEveryReport(t, first, filepath.Join(dir, "reports", "2026-10-01"))

	second, err := RunScanWithOptions(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range second.Findings.Findings() {
		if strings.HasPrefix(f.Location.FilePath, "reports/") {
			t.Errorf("%s reported in %s:%d (%q): the scan read a report nox wrote as if it were source",
				f.RuleID, f.Location.FilePath, f.Location.StartLine, f.Message)
		}
	}
	if got := len(second.Findings.Findings()); got != baseline {
		t.Errorf("scan 1 reported %d findings, scan 2 %d on the same tree plus nox's own reports", baseline, got)
	}

	// Nothing drops silently: every skipped file is named in the scan's own
	// account of what it did not read.
	var note *Degradation
	for i, d := range second.Degradations {
		if d.Kind == degradeGeneratedReport {
			note = &second.Degradations[i]
		}
	}
	if note == nil {
		t.Fatalf("no %s degradation; the skip is invisible. Degradations: %v", degradeGeneratedReport, second.Degradations)
	}
	if !note.Advisory {
		t.Error("skipping nox's own report must not fail a --fail-on-degraded build")
	}
	for _, p := range written {
		rel, _ := filepath.Rel(dir, p)
		if !strings.Contains(note.Detail, filepath.ToSlash(rel)) {
			t.Errorf("degradation does not name %s: %q", rel, note.Detail)
		}
	}
}

// The counterexample to skipping by content carelessly: a file that is not a
// nox report keeps being scanned, even when it is a report from another tool or
// mentions nox, and a credential committed in it is still found.
func TestAJSONFileThatIsNotANoxReportIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	key := seededAWSKey()
	files := map[string]string{
		// Another scanner's SARIF carries what it matched, verbatim. Skipping
		// it would hide a committed credential.
		"ci/gitleaks.sarif": `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": [{"ruleId": "aws-access-token", "locations": [{"physicalLocation": {"region": {"snippet": {"text": "` + key + `"}}}}]}]}]}`,
		// A package named nox, with the word in all the obvious places.
		"tools/package.json": `{"name": "nox", "description": "nox report helper", "config": {"aws_access_key_id": "` + key + `"}}`,
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "SEC-001" {
			found[f.Location.FilePath] = true
		}
	}
	for name := range files {
		if !found[name] {
			t.Errorf("SEC-001 not reported in %s: a real credential in a file that is not a nox report was dropped", name)
		}
	}
	for _, d := range res.Degradations {
		if d.Kind == degradeGeneratedReport {
			t.Errorf("a file was skipped as a nox report that is not one: %s", d.Detail)
		}
	}
}
