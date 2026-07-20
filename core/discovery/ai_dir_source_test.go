package discovery

import "testing"

// Source files living under a prompts/ or agents/ directory must classify as
// Source, not AIComponent. The taint, SAST, agentflow, slop, and variants
// analyzers all skip any artifact whose Type is not Source, so misclassifying
// this code silently drops it from injection/taint analysis — the worst place
// for a false negative, since prompt- and agent-driving code is the highest-risk
// code in the tree. Genuine AI-component artifacts (prompts, configs, agent
// docs) under the same directories must still classify as AIComponent.
func TestClassify_SourceUnderAIDirsIsSource(t *testing.T) {
	c := &DefaultClassifier{}

	source := []string{
		"internal/prompts/vuln.go",
		"pkg/prompts/builder.py",
		"src/agents/handler.ts",
		"app/agents/server.go",
		"lib/prompts/render.rb",
	}
	for _, p := range source {
		if got := c.Classify(p, nil); got != Source {
			t.Errorf("Classify(%q) = %q, want Source (must be reachable by taint/SAST)", p, got)
		}
	}

	aiComponent := []string{
		"prompts/summarize.prompt", // *.prompt
		"prompts/agent.md",         // markdown prompt doc, not source
		"agents/policy.yaml",       // config, not source
		"mcp.json",                 // mcp config
		"config/server.mcp.json",   // *.mcp.json
		"agents/system.prompt.md",  // *.prompt.md
	}
	for _, p := range aiComponent {
		if got := c.Classify(p, nil); got != AIComponent {
			t.Errorf("Classify(%q) = %q, want AIComponent (must stay in AI inventory)", p, got)
		}
	}
}
