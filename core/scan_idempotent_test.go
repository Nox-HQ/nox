package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A scan must not report findings on the artifacts it is about to overwrite.
//
// `--output` defaults to `.`, so the obvious invocation — `nox scan .` — writes
// findings.json into the tree it just scanned. The next run then scans that
// file, and a report of a finding contains the evidence for the finding: a
// finding's Message and matched text are in there verbatim.
//
// Measured 2026-09-12 on 64bit/async-openai, scanning the same clean tree three
// times with `--output .`:
//
//	scan 1   100 findings   AI-036 = 41
//	scan 2   141 findings   AI-036 = 82
//	scan 3   182 findings   AI-036 = 123
//
// AI-036 is "Using deprecated GPT-3.5 model". The repository's openapi.yaml
// legitimately contains 41 `gpt-3.5` strings; each becomes a finding, each
// finding is written into findings.json carrying the string that produced it,
// and the next scan finds all 41 again in the report. It grows without bound —
// scan N reports 100 + 41(N-1) — and every added finding is a duplicate of one
// nox already reported.
//
// This is the same shape as a nox:ignore comment firing the rule it waives:
// text ABOUT a finding causing the finding.

// scanTwice runs a scan of dir twice, writing the artifact into dir between
// runs the way `--output .` does, and returns both finding counts.
func scanTwice(t *testing.T, dir string) (first, second int) {
	t.Helper()
	run := func() int {
		res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, OutputDir: dir})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		fs := res.Findings.Findings()
		// Write the report back into the tree, exactly as the CLI does.
		body, err := json.Marshal(map[string]any{
			"meta":     map[string]string{"tool_name": "nox"},
			"findings": fs,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "findings.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		return len(fs)
	}
	first = run()
	second = run()
	return first, second
}

// TestAScanDoesNotReportOnItsOwnReport checks that scanning an unchanged tree
// twice reports the same findings both times.
func TestAScanDoesNotReportOnItsOwnReport(t *testing.T) {
	dir := t.TempDir()
	// A file whose finding text is itself matchable: the rule looks for the
	// model name, and the finding written about it carries that name.
	src := "model = \"gpt-3.5-turbo\"\nclient.chat(model=model)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	first, second := scanTwice(t, dir)
	if first == 0 {
		t.Skip("fixture produced no findings; nothing to amplify")
	}
	if second != first {
		t.Errorf("scan 1 reported %d findings and scan 2 reported %d on the same "+
			"unchanged tree. The report was scanned as if it were source, so every "+
			"run inflates the next one", first, second)
	}
}

// TestTheOutputArtifactsAreExcludedByName. OutputDir is what tells the scan
// which files are its own. Each artifact the pipeline writes must be covered,
// because one that is missed reintroduces the amplification for whichever rule
// happens to match that format.
func TestTheOutputArtifactsAreExcludedByName(t *testing.T) {
	for _, name := range OutputArtifactNames() {
		if name == "" {
			t.Error("an empty artifact name excludes nothing and matches everything")
		}
	}
	for _, want := range []string{"findings.json", "results.sarif", "ai.inventory.json"} {
		var found bool
		for _, got := range OutputArtifactNames() {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is written by a scan but is not excluded from one", want)
		}
	}
}

// TestAForeignArtifactIsStillScanned. Excluding by NAME would silently skip a
// findings.json that nox did not write — another tool's output, a file a
// project genuinely ships. Only the paths THIS scan will overwrite are
// excluded, so anything elsewhere in the tree is still read.
//
// The exclusion is root-anchored for exactly this reason: a gitignore pattern
// without a slash matches any path component, so a bare "findings.json" would
// skip reports/findings.json too — a real file dropped to suppress an artifact
// nox wrote, which trades a false positive for a false negative.
//
// The subdirectory is deliberately `reports/` and not `fixtures/`: nothing
// under fixtures/ is scanned at all, by default, whatever it contains. An
// earlier version of this test used that name and failed for a reason that had
// nothing to do with the exclusion — it could not distinguish the two states it
// was written to tell apart.
func TestAForeignArtifactIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "reports")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Same basename, different directory: not this scan's output.
	body := "{\"model\": \"gpt-3.5-turbo\"}\n"
	if err := os.WriteFile(filepath.Join(sub, "findings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Falsify the fixture first: without the exclusion this file MUST produce a
	// finding, or the assertion below passes for the wrong reason.
	base, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Findings.Findings()) == 0 {
		t.Fatal("fixture: reports/findings.json produces no finding even unexcluded, " +
			"so this test cannot tell an exclusion from an empty scan")
	}

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, OutputDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var sawSub bool
	for _, f := range res.Findings.Findings() {
		if filepath.Base(filepath.Dir(f.Location.FilePath)) == "reports" {
			sawSub = true
		}
	}
	if !sawSub {
		t.Error("reports/findings.json was skipped; excluding by basename rather " +
			"than by the exact output path drops real files")
	}
}
