package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An artifact has to state what the scan could not do, or a consumer reads its
// silence as an all-clear. Two things say so, and both die at the artifact
// boundary if an adapter forgets them:
//
//   - Degradations report what BROKE — a failed OSV lookup, a plugin that never
//     started, an unparsed lockfile.
//   - Capabilities report what was never POSSIBLE — an installation with no call
//     graph produces a scan with no call-graph errors and no call-graph answers.
//
// The CLI printed degradations to stderr and recorded them in findings.json.
// The MCP server built its JSON report without them at all, across three
// separate reporter sites. So an agent asking nox for its findings got an
// artifact that said nothing about the checks that had not run: the consumer
// least able to notice, because it has no stderr to read.
//
// That was fixed by assignment at each site, and this guard existed to keep the
// assignments in place. It is now a guard on something stronger: the fields are
// set by ScanResult.JSONReporter / ScanResult.SARIFReporter, once, next to the
// result they are derived from — so a new surface inherits them rather than
// remembering them. A site that builds a reporter by hand has opted out of that
// and must prove it did so deliberately.

// noScanBehindIt is the escape hatch, and it is deliberately a sentence a
// reader has to mean. A report with no ScanResult in reach — `nox mcp drift`
// compares two manifests — has no degradations and no capability matrix, and
// must say so rather than leave the omission looking like an oversight.
const noScanBehindIt = "no scan behind this report"

// adapterSources returns the non-test Go files in the CLI and MCP adapters.
func adapterSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{"cli", "server"} {
		entries, err := os.ReadDir(filepath.Join("..", dir))
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join("..", dir, name)
			raw, err := os.ReadFile(path) //nolint:gosec // repository source
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			out[dir+"/"+name] = string(raw)
		}
	}
	return out
}

// checkReporterSites walks every construction of a reporter and requires each
// one to either go through the shared constructor or set the field by hand.
//
// shared is the method that fills everything in ("JSONReporter("); bare is the
// raw constructor a hand-rolled site would call; field is what such a site must
// then assign. Returns the number of sites examined so the caller can assert
// the pattern has not drifted out from under the guard.
func checkReporterSites(t *testing.T, shared, bare, field, why string) int {
	t.Helper()
	var total int
	for file, src := range adapterSources(t) {
		lines := strings.Split(src, "\n")
		for i, line := range lines {
			viaShared := strings.Contains(line, shared)
			viaBare := strings.Contains(line, bare)
			if !viaShared && !viaBare {
				continue
			}
			total++
			// The shared constructor sets the field from the ScanResult. That
			// is the whole point of it existing, and such a site needs nothing.
			if viaShared {
				continue
			}
			// A hand-rolled site: the assignment follows the construction, and
			// an explicit exemption may sit just above it. Look both ways.
			window := strings.Join(lines[maxInt(i-5, 0):minInt(i+9, len(lines))], "\n")
			if strings.Contains(window, field) || strings.Contains(window, noScanBehindIt) {
				continue
			}
			t.Errorf("%s:%d builds a reporter by hand without setting %s. %s Use the "+
				"ScanResult constructor (%s), set the field explicitly, or write %q in a "+
				"comment if there is genuinely no scan to describe.",
				file, i+1, strings.TrimSuffix(strings.TrimPrefix(field, "."), " = "),
				why, shared, noScanBehindIt)
		}
	}
	return total
}

// TestEveryJSONReportCarriesDegradations pins that no adapter drops them.
func TestEveryJSONReportCarriesDegradations(t *testing.T) {
	total := checkReporterSites(t, ".JSONReporter(", "NewJSONReporter(", ".Degradations = ",
		"The artifact then cannot distinguish a clean scan from one whose checks did not run — "+
			"and an MCP client has no stderr to read instead.")
	if total < 4 {
		t.Errorf("only %d JSON reporter sites were found; the pattern has drifted and sites are "+
			"going unguarded", total)
	}
}

// TestEveryJSONReportCarriesCapabilities pins the other half.
//
// This one matters more than it looks, because an omitted capability matrix
// does not read as missing information. A findings.json with no `capabilities`
// key looks exactly like a scan that asked every question and found nothing —
// which is the single inference the capability model exists to prevent.
func TestEveryJSONReportCarriesCapabilities(t *testing.T) {
	total := checkReporterSites(t, ".JSONReporter(", "NewJSONReporter(", ".Capabilities = ",
		"A report with no capability matrix looks identical to one from an installation that "+
			"could answer every question.")
	if total < 4 {
		t.Errorf("only %d JSON reporter sites were found; the pattern has drifted and sites are "+
			"going unguarded", total)
	}
}

// TestEverySARIFReportCarriesCapabilities holds the same line for SARIF, where
// the consumer is usually GitHub Code Scanning and the failure is a green run.
func TestEverySARIFReportCarriesCapabilities(t *testing.T) {
	total := checkReporterSites(t, ".SARIFReporter(", "sarif.NewReporter(", ".Capabilities = ",
		"SARIF has no other slot for what the run could not establish, so Code Scanning shows a "+
			"scan that could not look and a scan that looked and found nothing identically.")
	if total < 4 {
		t.Errorf("only %d SARIF reporter sites were found; the pattern has drifted and sites are "+
			"going unguarded", total)
	}
}

// TestDegradationConversionHasOneImplementation keeps the conversion shared.
// It was duplicated in the CLI while the server had none, which is how the two
// surfaces came to disagree about whether degradations are part of a report.
func TestDegradationConversionHasOneImplementation(t *testing.T) {
	for file, src := range adapterSources(t) {
		if strings.Contains(src, "func degradationsForReport(") {
			t.Errorf("%s defines its own degradation conversion; use report.DegradationsFrom so "+
				"every surface reports the same thing", file)
		}
		if strings.Contains(src, "func capabilitiesForReport(") {
			t.Errorf("%s defines its own capability conversion; use report.CapabilitiesFrom so "+
				"findings.json and results.sarif cannot disagree about what nox could establish",
				file)
		}
	}
}

// maxInt returns the larger of two ints.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// minInt returns the smaller of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
