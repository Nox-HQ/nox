package deps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// End to end through the analyzer: an npm advisory whose nox_symbols lists an
// exported function, and a project that does or does not reference it.
func TestNpmSymbolReferenceEndToEnd(t *testing.T) {
	record := func() map[string][]vulnsource.Record {
		return map[string][]vulnsource.Record{"nodemailer": {{
			ID: "GHSA-js-sym", Summary: "address parser", Aliases: []string{"CVE-2026-0001"},
			Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "8.1"}},
			Symbols: []vulnsource.AffectedSymbols{{
				Ecosystem: "npm", Package: "nodemailer", Method: vulnsource.SymbolMethodPatchDiff, Status: "ok",
				Symbols: []vulnsource.ChangedSymbol{{Name: "parseAddresses", Package: "nodemailer/lib/addressparser", Confidence: "low"}},
			}},
		}}}
	}
	run := func(t *testing.T, app string) findings.Finding {
		dir, arts := npmLockfile(t, "nodemailer", "6.0.0")
		p := filepath.Join(dir, "src.js")
		if err := os.WriteFile(p, []byte(app), 0o600); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, discovery.Artifact{Path: "src.js", AbsPath: p, Type: discovery.Source})
		a := NewAnalyzer(WithSource(&stubSource{name: "stub", records: record()}), WithOSVBaseURL("http://127.0.0.1:1"))
		_, fs, err := a.ScanArtifacts(context.Background(), arts)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs.Findings() {
			if f.RuleID == "VULN-001" {
				return f
			}
		}
		t.Fatal("no VULN-001")
		return findings.Finding{}
	}

	used := run(t, "const { parseAddresses } = require('nodemailer/lib/addressparser');\nmodule.exports = (s) => parseAddresses(s);\n")
	if used.Metadata["applicability_reached"] != "call_reachable" || used.Metadata["affected_symbol_evidence"] != "source_reference" {
		t.Fatalf("a referenced listed export should reach call_reachable: %v", used.Metadata)
	}

	// Imports the package, but not the listed export: stays where it was, and is
	// never refuted.
	other := run(t, "const nm = require('nodemailer');\nnm.createTransport({});\n")
	if other.Metadata["applicability_reached"] == "call_reachable" || other.Metadata["applicability"] == "not_impacting" {
		t.Fatalf("an unreferenced listed export must change nothing: %v", other.Metadata)
	}
	if other.Metadata["applicability_reached"] != "symbol_used" {
		t.Errorf("package import should still reach symbol_used: %v", other.Metadata)
	}
}
