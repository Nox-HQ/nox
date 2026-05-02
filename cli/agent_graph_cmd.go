package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

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
		rendered = renderMermaid(&inv)
	case "dot":
		rendered = renderDot(&inv)
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

func renderMermaid(inv *ai.Inventory) string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	if len(inv.ToolMatrix) == 0 {
		b.WriteString("    empty[\"No agent tool registrations detected\"]\n")
		return b.String()
	}

	for i, set := range inv.ToolMatrix {
		agentID := mermaidNodeID("agent", i)
		fmt.Fprintf(&b, "    subgraph %s [%s]\n", agentID, sanitize(set.Agent))
		for j, tool := range set.Tools {
			toolID := mermaidNodeID(fmt.Sprintf("a%d_t", i), j)
			label := sanitize(tool)
			caps := capabilityLabels(set.Capabilities[tool])
			if caps != "" {
				label = label + "<br/><small>" + caps + "</small>"
			}
			fmt.Fprintf(&b, "        %s[\"%s\"]\n", toolID, label)
		}
		b.WriteString("    end\n")
	}
	return b.String()
}

func renderDot(inv *ai.Inventory) string {
	var b strings.Builder
	b.WriteString("digraph nox_agent_lattice {\n")
	b.WriteString("    rankdir=LR;\n")
	b.WriteString("    node [shape=box, style=rounded];\n")

	for i, set := range inv.ToolMatrix {
		clusterID := fmt.Sprintf("cluster_%d", i)
		fmt.Fprintf(&b, "    subgraph %s {\n", clusterID)
		fmt.Fprintf(&b, "        label=%q;\n", set.Agent)
		for j, tool := range set.Tools {
			nodeID := fmt.Sprintf("a%d_t%d", i, j)
			caps := capabilityLabels(set.Capabilities[tool])
			label := tool
			if caps != "" {
				label = tool + "\\n[" + caps + "]"
			}
			color := capabilityColor(set.Capabilities[tool])
			fmt.Fprintf(&b, "        %s [label=%q, fillcolor=%q, style=\"rounded,filled\"];\n", nodeID, label, color)
		}
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func mermaidNodeID(prefix string, n int) string {
	return fmt.Sprintf("%s%d", prefix, n)
}

func sanitize(s string) string {
	r := strings.NewReplacer("\"", "'", "\n", " ", "[", "(", "]", ")")
	return r.Replace(s)
}

func capabilityLabels(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	cp := make([]string, len(caps))
	copy(cp, caps)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// capabilityColor returns a graphviz fill colour reflecting the
// risk level of the strongest capability the tool carries.
func capabilityColor(caps []string) string {
	for _, c := range caps {
		switch c {
		case "shell_exec", "cloud_iam_modify", "payment_initiate":
			return "#ffcccc"
		}
	}
	for _, c := range caps {
		switch c {
		case "file_write", "database_write", "git_push", "read_secret":
			return "#ffe0b3"
		}
	}
	for _, c := range caps {
		switch c {
		case "file_read", "http_request", "email_send", "webhook_post":
			return "#fff5cc"
		}
	}
	return "#e8f4ff"
}
