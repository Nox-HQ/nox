package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeReportFixture(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The heads below are what each nox writer emits, trimmed to the fields the
// detector reads. The end-to-end test in core writes the real files with the
// real reporters; these pin the decision for each format in isolation.
func TestGeneratedReport_RecognisesWhatNoxWrites(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, body, want string
	}{
		{
			name: "sarif",
			file: "old-run.sarif",
			body: `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "nox", "version": "1.48.2",
				"rules": [{"id": "AI-009", "shortDescription": {"text": "LLM output passed to eval()"}}]}}}]}`,
			want: "SARIF",
		},
		{
			name: "findings json",
			file: "scan-2026-10-01.json",
			body: `{"meta": {"schema_version": "1.0.0", "tool_name": "nox", "tool_version": "1.48.2"}, "findings": []}`,
			want: "nox JSON report",
		},
		{
			name: "evidence artifact",
			file: "evidence.json",
			body: `{"meta": {"schema_version": "1.0.0", "tool_name": "nox", "adjudicator_version": "1"}, "capabilities": []}`,
			want: "nox JSON report",
		},
		{
			name: "cyclonedx",
			file: "bom.json",
			// "version" is a number here and a string in SARIF; the writer
			// emits it, so the fixture does.
			body: `{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"tools": [{"vendor": "nox", "name": "nox", "version": "1.48.2"}]}, "components": []}`,
			want: "CycloneDX SBOM",
		},
		{
			name: "spdx",
			file: "deps.spdx.json",
			body: `{"spdxVersion": "SPDX-2.3", "creationInfo": {"created": "2026-10-24T12:00:26Z", "creators": ["Tool: nox-1.48.2"]}, "packages": []}`,
			want: "SPDX SBOM",
		},
		{
			name: "attack plan",
			file: "hypotheses.json",
			body: `{"schema_version": "attack-plan/1", "root": ".", "assets": [], "hypotheses": []}`,
			want: "attack plan",
		},
		{
			name: "html report",
			file: "index.html",
			body: "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<title>Nox Security Report</title>\n</head>\n<body>\n<h1>Nox Security Report</h1>\n</body></html>\n",
			want: "HTML report",
		},
		{
			name: "compact sarif, upper-case extension",
			file: "RESULTS.SARIF",
			body: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"nox"}}}]}`,
			want: "SARIF",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := GeneratedReport(writeReportFixture(t, tc.file, tc.body))
			if !ok || got != tc.want {
				t.Fatalf("GeneratedReport = (%q, %v), want (%q, true)", got, ok, tc.want)
			}
		})
	}
}

// Every case here is a real file a project could commit. Each must stay
// scanned: skipping it would trade a false positive nox caused for a false
// negative the project pays for.
func TestGeneratedReport_LeavesEverythingElseAlone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, body string
	}{
		{
			// A package named nox, with a credential in it. The word is there;
			// the claim to be a nox report is not.
			name: "package.json named nox",
			file: "package.json",
			body: `{"name": "nox", "version": "1.0.0", "config": {"token": "ghp_0123456789abcdefghijklmnopqrstuvwxyz"}}`,
		},
		{
			name: "hand-edited json mentioning nox",
			file: "settings.json",
			body: `{"scanner": "nox", "notes": "run nox before merging", "tool_name": "deploy", "aws_secret_access_key": "x"}`,
		},
		{
			// tool_name is nox, but not where a nox report puts it.
			name: "tool_name nox outside meta",
			file: "pipeline.json",
			body: `{"steps": [{"tool_name": "nox", "args": ["scan", "."]}]}`,
		},
		{
			name: "another tool's sarif",
			file: "semgrep.sarif",
			body: `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}}]}`,
		},
		{
			// One run is nox's and one is not. The other tool's run may carry
			// what it matched, verbatim, so the file is not nox's own words.
			name: "merged sarif with a foreign run",
			file: "merged.sarif",
			body: `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "nox"}}}, {"tool": {"driver": {"name": "gitleaks"}}}]}`,
		},
		{
			name: "another tool's cyclonedx",
			file: "sbom.cdx.json",
			body: `{"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"tools": [{"vendor": "anchore", "name": "syft"}]}, "components": [{"name": "nox"}]}`,
		},
		{
			name: "another tool's spdx",
			file: "sbom.spdx.json",
			body: `{"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: syft-1.0.0"]}, "packages": [{"name": "nox-hq"}]}`,
		},
		{
			// The marker survives in the prefix, the document does not parse.
			// Nothing confirms it is a report, so it is scanned.
			name: "truncated nox sarif",
			file: "results.sarif",
			body: `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "nox", "rules": [`,
		},
		{
			name: "html page titled differently",
			file: "index.html",
			body: "<html><head><title>Nox docs</title></head><body><h1>Nox Security Report</h1></body></html>",
		},
		{
			name: "source file mentioning a report",
			file: "make_report.py",
			body: `print('{"meta": {"tool_name": "nox"}}')`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, ok := GeneratedReport(writeReportFixture(t, tc.file, tc.body)); ok {
				t.Fatalf("GeneratedReport = (%q, true): %s would no longer be scanned", got, tc.file)
			}
		})
	}
}

// The marker has to be near the top. A nox report puts it within the first
// few hundred bytes; a file that only mentions it deep inside is something
// else, and is not decoded in full to find out.
func TestGeneratedReport_MarkerMustBeInThePrefix(t *testing.T) {
	t.Parallel()
	body := `{"padding": "` + strings.Repeat("a", 2*reportSniffBytes) + `", "meta": {"schema_version": "1.0.0", "tool_name": "nox"}}`
	if got, ok := GeneratedReport(writeReportFixture(t, "late.json", body)); ok {
		t.Fatalf("GeneratedReport = (%q, true) for a marker past the sniffed prefix", got)
	}
}

func TestGeneratedReport_MissingFile(t *testing.T) {
	t.Parallel()
	if _, ok := GeneratedReport(filepath.Join(t.TempDir(), "absent.sarif")); ok {
		t.Fatal("a file that cannot be read is not a report")
	}
}
