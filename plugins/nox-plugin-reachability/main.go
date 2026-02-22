package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/reachability", version).
		Capability("reachability", "Import-based reachability analysis for vulnerability findings").
		ToolWithContext("analyze_reachability", "Classify VULN findings as reachable, unreachable, or undetermined based on import analysis", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("analyze_reachability", handleAnalyzeReachability)
}

func handleAnalyzeReachability(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	workspaceRoot := req.InputString("workspace_root")
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	// Extract VULN findings from scan context.
	vulns := extractVulnFindings(req.Findings())
	if len(vulns) == 0 {
		return resp.Build(), nil
	}

	// Extract imports from workspace (if workspace is available).
	imports := NewImportSet()
	if workspaceRoot != "" {
		var err error
		imports, err = ExtractImports(workspaceRoot)
		if err != nil {
			return nil, fmt.Errorf("extracting imports: %w", err)
		}
	}

	// Cross-reference vulns against imports.
	results := Analyze(vulns, imports)

	// Emit findings and enrichments.
	for _, r := range results {
		switch r.RuleID {
		case "REACH-001":
			resp.Finding(
				"REACH-001",
				sdk.SeverityInfo,
				sdk.ConfidenceHigh,
				fmt.Sprintf("Vulnerable package %s (%s) is NOT imported — likely false positive", r.Vuln.Package, r.Vuln.VulnID),
			).
				WithMetadata("package", r.Vuln.Package).
				WithMetadata("ecosystem", r.Vuln.Ecosystem).
				WithMetadata("vuln_id", r.Vuln.VulnID).
				WithMetadata("reachable", "false").
				WithFingerprint(fmt.Sprintf("REACH-001:%s:%s", r.Vuln.Package, r.Vuln.VulnID)).
				Done()

		case "REACH-002":
			resp.Finding(
				"REACH-002",
				sdk.SeverityHigh,
				sdk.ConfidenceMedium,
				fmt.Sprintf("Vulnerable package %s (%s) IS imported — confirmed risk", r.Vuln.Package, r.Vuln.VulnID),
			).
				WithMetadata("package", r.Vuln.Package).
				WithMetadata("ecosystem", r.Vuln.Ecosystem).
				WithMetadata("vuln_id", r.Vuln.VulnID).
				WithMetadata("reachable", "true").
				WithFingerprint(fmt.Sprintf("REACH-002:%s:%s", r.Vuln.Package, r.Vuln.VulnID)).
				Done()

		case "REACH-003":
			resp.Finding(
				"REACH-003",
				sdk.SeverityLow,
				sdk.ConfidenceLow,
				fmt.Sprintf("Cannot determine reachability for %s (%s) — unsupported ecosystem %s", r.Vuln.Package, r.Vuln.VulnID, r.Vuln.Ecosystem),
			).
				WithMetadata("package", r.Vuln.Package).
				WithMetadata("ecosystem", r.Vuln.Ecosystem).
				WithMetadata("vuln_id", r.Vuln.VulnID).
				WithMetadata("reachable", "undetermined").
				WithFingerprint(fmt.Sprintf("REACH-003:%s:%s", r.Vuln.Package, r.Vuln.VulnID)).
				Done()
		}

		// Enrich the original VULN finding.
		if r.Vuln.Fingerprint != "" {
			reachable := "undetermined"
			switch r.Status {
			case ReachReachable:
				reachable = "true"
			case ReachUnreachable:
				reachable = "false"
			}

			resp.Enrichment(r.Vuln.Fingerprint, "reachability", fmt.Sprintf("Reachability: %s for %s", reachable, r.Vuln.Package)).
				Body(fmt.Sprintf("Package `%s` reachability: **%s**", r.Vuln.Package, reachable)).
				WithMetadata("reachable", reachable).
				WithMetadata("package", r.Vuln.Package).
				WithMetadata("ecosystem", r.Vuln.Ecosystem).
				Source("nox/reachability").
				Done()
		}
	}

	return resp.Build(), nil
}

// extractVulnFindings filters findings to VULN-* rules and extracts metadata.
func extractVulnFindings(findings []*pluginv1.Finding) []VulnInfo {
	var vulns []VulnInfo
	for _, f := range findings {
		ruleID := f.GetRuleId()
		if len(ruleID) < 5 || ruleID[:5] != "VULN-" {
			continue
		}
		meta := f.GetMetadata()
		if meta == nil {
			continue
		}
		pkg := meta["package"]
		ecosystem := meta["ecosystem"]
		vulnID := meta["vuln_id"]
		if pkg == "" || ecosystem == "" {
			continue
		}

		fingerprint := f.GetFingerprint()
		if fingerprint == "" {
			loc := f.GetLocation()
			file := ""
			line := 0
			if loc != nil {
				file = loc.GetFilePath()
				line = int(loc.GetStartLine())
			}
			fingerprint = fmt.Sprintf("%s:%s:%d", ruleID, file, line)
		}

		vulns = append(vulns, VulnInfo{
			Fingerprint: fingerprint,
			Package:     pkg,
			Ecosystem:   ecosystem,
			VulnID:      vulnID,
		})
	}
	return vulns
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-reachability: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return buildServer().Serve(ctx)
}
