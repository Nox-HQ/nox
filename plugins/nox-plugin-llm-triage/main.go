// nox-plugin-llm-triage — optional LLM second-opinion triage.
//
// nox's core is deterministic and offline; this plugin is the opt-in escape
// hatch for teams that want an LLM's judgment on top. It consumes the scan's
// findings (scan context), sends each finding plus a small code snippet to a
// configured chat endpoint, and attaches a triage verdict
// (true-positive / false-positive / uncertain) as an enrichment on the original
// finding. It never changes the scan result — enrichments annotate, they don't
// gate.
//
// Active egress: the plugin sends your source snippets to a third-party model.
// Operators must opt in explicitly with `authorize: true`; without it the tool
// refuses to run. The deterministic core is unaffected whether or not this
// plugin is installed.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/llm-triage", version).
		Capability("llm-triage", "Optional LLM second-opinion triage — judges each finding true/false positive and annotates it. Never gates the scan.").
		ToolWithContext("llm_triage", "Send each finding + code snippet to a chat endpoint and attach a true/false-positive verdict (active: egress of source, needs confirmation)", true).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithNetworkHosts("*"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("llm_triage", handleTriage)
}

func handleTriage(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	endpoint := req.InputString("endpoint")
	if endpoint == "" {
		return resp.Build(), fmt.Errorf("llm_triage requires `endpoint` (URL of an OpenAI-compatible chat-completions endpoint)")
	}

	// Egress consent gate. This tool sends your source code to a third-party
	// model; require explicit authorization so a stray config or hostile prompt
	// can't exfiltrate code silently.
	authorize, _ := req.Input["authorize"].(bool)
	if !authorize {
		return resp.Build(), fmt.Errorf(
			"llm_triage sends your source snippets to the configured LLM endpoint. Set `authorize: true` to confirm you accept sending code to %s", endpoint)
	}

	if !req.HasScanContext() || len(req.Findings()) == 0 {
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, "llm-triage: no findings to triage", "llm-triage")
		return resp.Build(), nil
	}

	workspaceRoot := req.InputString("workspace_root")
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}
	maxFindings := 0
	if v, ok := req.Input["max_findings"].(float64); ok {
		maxFindings = int(v)
	}

	client := newHTTPLLMClient(endpoint, req.InputString("model"), req.InputString("auth_header"))
	read := fileSnippetReader(workspaceRoot, 6)

	verdicts, err := triageFindings(ctx, client, read, req.Findings(), TriageOptions{
		MaxFindings:        maxFindings,
		MinSeverity:        minSeverityFromInput(req.InputString("min_severity")),
		SkipHighConfidence: boolInput(req.Input, "skip_high_confidence", true),
		OnlyRules:          listInput(req.Input, "only_rules"),
		SkipRules:          listInput(req.Input, "skip_rules"),
	})
	if err != nil {
		return resp.Build(), err
	}

	emitVerdicts(resp, verdicts)
	resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, summarize(verdicts), "llm-triage")
	return resp.Build(), nil
}

// emitVerdicts attaches one enrichment per verdict to the originating finding.
func emitVerdicts(resp *sdk.ResponseBuilder, verdicts []Verdict) {
	for i := range verdicts {
		v := &verdicts[i]
		if v.Fingerprint == "" {
			continue // cannot anchor an enrichment without a fingerprint
		}
		conf := sdk.ConfidenceMedium
		if v.Disposition == DispUncertain {
			conf = sdk.ConfidenceLow
		}
		resp.Enrichment(v.Fingerprint, "llm-triage", "LLM triage: "+string(v.Disposition)).
			Body(triageBody(v)).
			WithMetadata("disposition", string(v.Disposition)).
			WithMetadata("rationale", v.Rationale).
			WithConfidence(conf).
			Source("nox/llm-triage").
			Done()
	}
}

func triageBody(v *Verdict) string {
	if v.Rationale == "" {
		return "LLM verdict: **" + string(v.Disposition) + "**"
	}
	return "LLM verdict: **" + string(v.Disposition) + "** — " + v.Rationale
}

// boolInput reads a boolean tool parameter, returning def when the key is
// absent so a defaulted-on gate (like skip_high_confidence) stays on unless the
// operator explicitly sets it false.
func boolInput(input map[string]any, key string, def bool) bool {
	if v, ok := input[key].(bool); ok {
		return v
	}
	return def
}

// listInput reads a rule-pattern list parameter. It accepts either a JSON array
// of strings or a single comma-separated string (both are common in tool
// configs), returning nil when absent or empty so an unset filter is a no-op.
func listInput(input map[string]any, key string) []string {
	raw, ok := input[key]
	if !ok {
		return nil
	}
	var out []string
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
	case string:
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func minSeverityFromInput(s string) Severity {
	switch s {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-llm-triage: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return buildServer().Serve(ctx)
}
