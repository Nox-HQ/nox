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
	manifest := sdk.NewManifest("nox/red-team", version).
		Capability("red-team", "Attack path analysis and exploit validation for security findings").
		Tool("analyze", "Analyze attack chains from security findings (passive, read-only)", true).
		Tool("validate", "Validate exploitability of specific findings (active, needs confirmation)", false).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithNetworkHosts("*"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("analyze", handleAnalyze).
		HandleTool("validate", handleValidate)
}

func handleAnalyze(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	contextFindings := req.Findings()
	aiAnalyze, _ := req.Input["ai_analyze"].(bool)

	chains := detectAttackChains(contextFindings)

	for _, chain := range chains {
		resp.Finding(
			chain.RuleID,
			chain.Severity,
			sdk.ConfidenceHigh,
			chain.Message,
		).
			WithMetadata("category", "attack-chain").
			WithMetadata("chain_steps", chain.Steps).
			WithMetadata("blast_radius", chain.BlastRadius).
			Done()
	}

	if aiAnalyze && len(chains) > 0 {
		built := resp.Build()
		provider, model, provErr := resolveProvider()
		if provErr != nil {
			markRedTeamError(built.GetFindings(), provErr.Error())
		} else {
			aiFindings := aiAttackAnalysis(ctx, provider, model, built.GetFindings(), contextFindings)
			if aiFindings != nil {
				built.Findings = append(built.Findings, aiFindings...)
			}
		}
		return built, nil
	}

	return resp.Build(), nil
}

func handleValidate(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	targetURL, _ := req.Input["target_url"].(string)
	if targetURL == "" {
		return resp.Build(), nil
	}

	findingIDs, _ := req.Input["finding_ids"].([]any)
	techniques, _ := req.Input["techniques"].([]any)

	techSet := make(map[string]bool)
	for _, t := range techniques {
		if s, ok := t.(string); ok {
			techSet[s] = true
		}
	}

	requestedIDs := make(map[string]bool)
	for _, id := range findingIDs {
		if s, ok := id.(string); ok {
			requestedIDs[s] = true
		}
	}

	results := runValidation(ctx, targetURL, requestedIDs, techSet)

	for _, r := range results {
		fb := resp.Finding(r.RuleID, r.Severity, r.Confidence, r.Message)
		fb.WithMetadata("category", "validation")
		fb.WithMetadata("validated", fmt.Sprintf("%t", r.Validated))
		fb.WithMetadata("technique", r.Technique)
		if r.Proof != "" {
			fb.WithMetadata("proof", r.Proof)
		}
		fb.Done()
	}

	return resp.Build(), nil
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-red-team: %v\n", err)
		return 1
	}
	return 0
}
