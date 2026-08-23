package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/analyzers/ai"
)

// runAgentGraph renders the agent capability lattice for a project.
// Source data is the ai.inventory.json output of a prior `nox scan`;
// rendered as Mermaid (default — embeds in GitHub markdown / docs)
// or Graphviz dot (for richer visualisations / compliance reports).
//
// Each detected agent file becomes one subgraph; tool nodes are
// coloured by capability tag; dangerous combinations get an explicit
// edge highlighting the LLM07 violation.
func runAgentGraph(args []string) int {
	fs := flag.NewFlagSet("agent-graph", flag.ContinueOnError)
	var (
		inputPath string
		format    string
		output    string
	)
	fs.StringVar(&inputPath, "input", "ai.inventory.json", "path to ai.inventory.json from a previous scan")
	fs.StringVar(&format, "format", "mermaid", "render format: mermaid or dot")
	fs.StringVar(&output, "output", "", "destination path (defaults to stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}
	var inv ai.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	var rendered string
	switch format {
	case "mermaid":
		rendered = ai.RenderMermaid(&inv)
	case "dot":
		rendered = ai.RenderDot(&inv)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q (use mermaid or dot)\n", format)
		return 2
	}

	if output == "" {
		fmt.Print(rendered)
		return 0
	}
	if err := os.WriteFile(output, []byte(rendered), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	fmt.Printf("nox agent-graph: wrote %s (%d agents)\n", output, len(inv.ToolMatrix))
	return 0
}
