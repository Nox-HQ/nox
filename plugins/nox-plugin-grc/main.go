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
	manifest := sdk.NewManifest("nox/grc", version).
		Capability("grc", "Governance, Risk & Compliance assessment with framework coverage and gap analysis").
		Tool("assess", "Run compliance assessment against specified frameworks", true).
		Tool("gap_report", "Generate comprehensive gap analysis for a framework", true).
		Tool("evidence", "Collect compliance evidence for framework controls", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("assess", handleAssess).
		HandleTool("gap_report", handleGapReport).
		HandleTool("evidence", handleEvidence)
}

func handleAssess(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	_ = ctx
	resp := sdk.NewResponse()

	frameworkNames, _ := req.Input["frameworks"].([]any)
	if len(frameworkNames) == 0 {
		resp.Finding("GRC-002", sdk.SeverityMedium, sdk.ConfidenceHigh,
			"Framework coverage below threshold: no frameworks specified for assessment").
			WithMetadata("category", "compliance-gap").
			Done()
		return resp.Build(), nil
	}

	aiAssess, _ := req.Input["ai_assess"].(bool)
	contextFindings := req.Findings()

	for _, name := range frameworkNames {
		fwName, ok := name.(string)
		if !ok {
			continue
		}
		fw, exists := frameworksByName[fwName]
		if !exists {
			continue
		}

		assessment := assessFramework(fw, contextFindings)

		if assessment.CoveragePercent < fw.Threshold {
			resp.Finding("GRC-002", sdk.SeverityMedium, sdk.ConfidenceHigh,
				fmt.Sprintf("Framework coverage below threshold: %s at %.1f%% (threshold: %.1f%%)", fw.Name, assessment.CoveragePercent, fw.Threshold)).
				WithMetadata("framework", fw.ID).
				WithMetadata("coverage", fmt.Sprintf("%.1f", assessment.CoveragePercent)).
				WithMetadata("threshold", fmt.Sprintf("%.1f", fw.Threshold)).
				WithMetadata("category", "compliance-gap").
				Done()
		}

		for _, gap := range assessment.CriticalGaps {
			resp.Finding("GRC-001", sdk.SeverityHigh, sdk.ConfidenceHigh,
				fmt.Sprintf("Critical control gap: no evidence for %s control %s — %s", fw.Name, gap.ControlID, gap.Description)).
				WithMetadata("framework", fw.ID).
				WithMetadata("control_id", gap.ControlID).
				WithMetadata("category", "control-gap").
				Done()
		}

		for _, finding := range assessFrameworkSpecific(fw, assessment) {
			resp.Finding(finding.RuleID, finding.Severity, sdk.ConfidenceHigh, finding.Message).
				WithMetadata("framework", fw.ID).
				WithMetadata("category", finding.Category).
				Done()
		}
	}

	if aiAssess {
		built := resp.Build()
		if len(built.GetFindings()) > 0 {
			provider, model, provErr := resolveProvider()
			if provErr != nil {
				markGapError(built.GetFindings(), provErr.Error())
			} else {
				aiGapAnalysis(ctx, provider, model, built.GetFindings())
			}
		}
		return built, nil
	}

	return resp.Build(), nil
}

func handleGapReport(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	_ = ctx
	resp := sdk.NewResponse()

	fwName, _ := req.Input["framework"].(string)
	if fwName == "" {
		return resp.Build(), nil
	}

	fw, exists := frameworksByName[fwName]
	if !exists {
		return resp.Build(), nil
	}

	contextFindings := req.Findings()
	report := generateGapReport(fw, contextFindings)

	if report.CoveragePercent < fw.Threshold {
		resp.Finding("GRC-002", sdk.SeverityMedium, sdk.ConfidenceHigh,
			fmt.Sprintf("Framework coverage below threshold: %s at %.1f%%", fw.Name, report.CoveragePercent)).
			WithMetadata("framework", fw.ID).
			WithMetadata("covered_controls", fmt.Sprintf("%d", report.CoveredCount)).
			WithMetadata("total_controls", fmt.Sprintf("%d", report.TotalControls)).
			WithMetadata("coverage", fmt.Sprintf("%.1f", report.CoveragePercent)).
			WithMetadata("category", "gap-report").
			Done()
	}

	for _, gap := range report.UncoveredControls {
		sev := sdk.SeverityMedium
		if gap.Priority == "high" {
			sev = sdk.SeverityHigh
		}
		resp.Finding("GRC-001", sev, sdk.ConfidenceHigh,
			fmt.Sprintf("Uncovered control: %s %s — %s", fw.Name, gap.ControlID, gap.Description)).
			WithMetadata("framework", fw.ID).
			WithMetadata("control_id", gap.ControlID).
			WithMetadata("priority", gap.Priority).
			WithMetadata("category", "gap-report").
			Done()
	}

	return resp.Build(), nil
}

func handleEvidence(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	_ = ctx
	resp := sdk.NewResponse()

	fwName, _ := req.Input["framework"].(string)
	if fwName == "" {
		return resp.Build(), nil
	}

	fw, exists := frameworksByName[fwName]
	if !exists {
		return resp.Build(), nil
	}

	controlID, _ := req.Input["control_id"].(string)
	contextFindings := req.Findings()

	evidence := collectEvidence(fw, controlID, contextFindings)

	for _, item := range evidence {
		if item.Stale {
			resp.Finding("GRC-003", sdk.SeverityMedium, sdk.ConfidenceHigh,
				fmt.Sprintf("Stale compliance evidence: %s control %s evidence is older than 90 days", fw.Name, item.ControlID)).
				WithMetadata("framework", fw.ID).
				WithMetadata("control_id", item.ControlID).
				WithMetadata("category", "stale-evidence").
				Done()
		}
	}

	if len(evidence) == 0 {
		resp.Finding("GRC-001", sdk.SeverityHigh, sdk.ConfidenceHigh,
			fmt.Sprintf("Critical control gap: no evidence found for %s%s", fw.Name, controlSuffix(controlID))).
			WithMetadata("framework", fw.ID).
			WithMetadata("category", "missing-evidence").
			Done()
	}

	return resp.Build(), nil
}

func controlSuffix(controlID string) string {
	if controlID != "" {
		return " control " + controlID
	}
	return ""
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-grc: %v\n", err)
		return 1
	}
	return 0
}
