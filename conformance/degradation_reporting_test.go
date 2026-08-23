package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A degradation says a check did not run, so "no findings" does not mean
// "nothing to find". That distinction is only useful if it reaches the person —
// or the agent — reading the results.
//
// The CLI printed degradations to stderr and recorded them in findings.json.
// The MCP server built its JSON report without them at all, across three
// separate reporter sites. So an agent asking nox for its findings got an
// artifact that said nothing about the checks that had not run: the consumer
// least able to notice, because it has no stderr to read.
//
// This guard requires every JSONReporter construction to set Degradations.

// reporterSites returns the non-test Go files that construct a JSON reporter.
func reporterSites(t *testing.T) map[string]string {
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
			if strings.Contains(string(raw), "NewJSONReporter(") {
				out[dir+"/"+name] = string(raw)
			}
		}
	}
	return out
}

// TestEveryJSONReportCarriesDegradations pins that no adapter drops them.
func TestEveryJSONReportCarriesDegradations(t *testing.T) {
	sites := reporterSites(t)
	if len(sites) == 0 {
		t.Fatal("found no JSON reporter construction sites; the guard is vacuous")
	}

	var total int
	for file, src := range sites {
		lines := strings.Split(src, "\n")
		for i, line := range lines {
			if !strings.Contains(line, "NewJSONReporter(") {
				continue
			}
			total++
			// The assignment follows the construction; an explicit "no
			// degradations" note may sit just above it. Look both ways.
			window := strings.Join(lines[maxInt(i-4, 0):minInt(i+8, len(lines))], "\n")
			if strings.Contains(window, ".Degradations = ") {
				continue
			}
			// A site with no ScanResult in reach has nothing to report; it must
			// say so rather than leave the omission looking like an oversight.
			if strings.Contains(window, "no degradations") {
				continue
			}
			t.Errorf("%s:%d constructs a JSON reporter without setting Degradations. The artifact "+
				"then cannot distinguish a clean scan from one whose checks did not run — and an "+
				"MCP client has no stderr to read instead. Set it from the ScanResult, or say "+
				"\"no degradations\" in a comment if none are in reach.", file, i+1)
		}
	}
	if total < 4 {
		t.Errorf("only %d reporter sites were checked; the pattern has drifted and sites are going "+
			"unguarded", total)
	}
}

// TestDegradationConversionHasOneImplementation keeps the conversion shared.
// It was duplicated in the CLI while the server had none, which is how the two
// surfaces came to disagree about whether degradations are part of a report.
func TestDegradationConversionHasOneImplementation(t *testing.T) {
	for file, src := range reporterSites(t) {
		if strings.Contains(src, "func degradationsForReport(") {
			t.Errorf("%s defines its own degradation conversion; use report.DegradationsFrom so "+
				"every surface reports the same thing", file)
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
