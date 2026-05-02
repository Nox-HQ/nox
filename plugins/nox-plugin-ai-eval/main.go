// nox-plugin-ai-eval — adversarial prompt corpus runner.
//
// On the dynamic-runtime track. Active risk: the plugin sends real
// HTTP traffic to the configured endpoint. Operators must opt in
// explicitly by passing the endpoint URL; the plugin will not
// auto-discover targets.
//
// Findings emitted:
//
//   AI-EVAL-001 (high)     — jailbreak / instruction-override succeeded
//   AI-EVAL-002 (high)     — system-prompt extraction succeeded
//   AI-EVAL-003 (medium)   — role / persona confusion succeeded
//   AI-EVAL-004 (critical) — tool misuse succeeded (file read, exfil)

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
	manifest := sdk.NewManifest("nox/ai-eval", version).
		Capability("ai-eval", "Adversarial prompt corpus runner — fires bundled jailbreak / system-leak / role-confusion attacks against a configured chat endpoint and reports which succeeded.").
		Tool("ai_eval", "Run the bundled adversarial prompt corpus against a chat endpoint (active, network, needs confirmation)", false).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithNetworkHosts("*"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("ai_eval", handleAIEval)
}

// ruleForKind maps an attack-classification kind to the public rule
// ID and severity exposed in the finding.
func ruleForKind(kind AttackKind, severityHint string) (ruleID, severity, cwe string) {
	switch kind {
	case AttackJailbreak:
		return "AI-EVAL-001", elevateSeverity(severityHint, "high"), "CWE-77"
	case AttackSystemLeak:
		return "AI-EVAL-002", elevateSeverity(severityHint, "high"), "CWE-200"
	case AttackRoleConfusion:
		return "AI-EVAL-003", elevateSeverity(severityHint, "medium"), "CWE-77"
	case AttackToolMisuse:
		return "AI-EVAL-004", elevateSeverity(severityHint, "critical"), "CWE-862"
	}
	return "AI-EVAL-001", "medium", "CWE-77"
}

// elevateSeverity prefers the corpus entry's severity when present,
// falling back to the per-kind default.
func elevateSeverity(hint, fallback string) string {
	if hint == "" {
		return fallback
	}
	return hint
}

// handleAIEval runs the corpus and emits findings for every successful
// attack.
func handleAIEval(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	endpoint, _ := req.Input["endpoint"].(string)
	payloadTemplate, _ := req.Input["payload_template"].(string)
	authHeader, _ := req.Input["auth_header"].(string)
	responsePath, _ := req.Input["response_path"].(string)
	authorize, _ := req.Input["authorize"].(bool)
	authorizedFor, _ := req.Input["authorized_target"].(string)

	resp := sdk.NewResponse()

	if endpoint == "" {
		return resp.Build(), fmt.Errorf("ai_eval requires `endpoint` (URL of the chat endpoint to test)")
	}
	// Active-attack consent gate. The corpus contains real
	// jailbreak-class prompts and runs them at the configured
	// endpoint. Operators must explicitly authorize each target so a
	// hostile prompt or accidental config can't aim the corpus at a
	// third-party endpoint. Both flags must be present and
	// authorized_target must match endpoint exactly.
	if !authorize || authorizedFor == "" {
		return resp.Build(), fmt.Errorf(
			"ai_eval is an active attack tool. Set `authorize: true` and `authorized_target: <endpoint>` to confirm you own or have written permission to test the target. The bundled corpus includes jailbreak / prompt-leak / role-confusion prompts; running them against an endpoint you don't own is unauthorised testing")
	}
	if authorizedFor != endpoint {
		return resp.Build(), fmt.Errorf(
			"authorized_target %q does not match endpoint %q. The two must be byte-identical so consent can't be smuggled across endpoints",
			authorizedFor, endpoint)
	}
	if payloadTemplate == "" {
		// OpenAI-shape default. Operators can override.
		payloadTemplate = `{"model":"gpt-4o","messages":[{"role":"user","content":"{{prompt}}"}]}`
	}
	if responsePath == "" {
		responsePath = "choices.0.message.content"
	}

	cfg := EvalConfig{
		Endpoint:        endpoint,
		PayloadTemplate: payloadTemplate,
		AuthHeader:      authHeader,
		ResponsePath:    responsePath,
		Concurrency:     1, // be polite; operators can extend later
	}

	verdicts := Evaluate(ctx, cfg, Corpus())

	for i := range verdicts {
		v := &verdicts[i]
		if !v.Success {
			continue
		}
		ruleID, severity, cwe := ruleForKind(v.Entry.Kind, v.Entry.Severity)
		fb := resp.Finding(
			ruleID,
			toSeverity(severity),
			sdk.ConfidenceHigh,
			fmt.Sprintf("Endpoint succumbed to %s (%s): marker %q matched in response", v.Entry.Kind, v.Entry.ID, v.Marker),
		)
		fb.WithMetadata("category", "ai-eval")
		fb.WithMetadata("attack_id", v.Entry.ID)
		fb.WithMetadata("attack_kind", string(v.Entry.Kind))
		fb.WithMetadata("matched_marker", v.Marker)
		fb.WithMetadata("http_status", fmt.Sprintf("%d", v.Status))
		fb.WithMetadata("response_excerpt", v.Body)
		fb.WithMetadata("cwe", cwe)
		fb.Done()
	}

	resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, SummariseVerdicts(verdicts), "ai-eval")
	return resp.Build(), nil
}

func toSeverity(s string) pluginv1.Severity {
	switch s {
	case "critical":
		return sdk.SeverityCritical
	case "high":
		return sdk.SeverityHigh
	case "low":
		return sdk.SeverityLow
	case "info":
		return sdk.SeverityInfo
	default:
		return sdk.SeverityMedium
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ai-eval plugin: %v\n", err)
		os.Exit(1)
	}
}
