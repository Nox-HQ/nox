package ai

import (
	"fmt"
	"sort"
	"strings"
)

// Rendering the agent capability lattice is domain logic, not adapter logic.
//
// It projects an Inventory's tool-permission matrix into Mermaid or Graphviz,
// and — critically — colours each tool by the RISK of the strongest capability
// it holds. That risk tiering is a security judgment ("shell_exec and
// payment_initiate are the dangerous ones"), and a security judgment restated in
// each entry point is a judgment that will diverge between them. It lived in two
// copies — the CLI's and the MCP server's — and had already drifted: the server
// copy silently dropped the risk colouring, the label sanitisation, and the
// empty-inventory case. Consolidating here makes the lattice look the same, and
// weigh risk the same, wherever nox renders it.

// dangerCapabilities are the highest-risk capabilities: a tool that can run
// shell commands, modify cloud IAM, or initiate payments can cause irreversible
// harm on its own. Rendered in red.
var dangerCapabilities = map[CapabilityTag]bool{
	CapShellExec:       true,
	CapCloudIAMModify:  true,
	CapPaymentInitiate: true,
}

// writeCapabilities are the write/escalation tier: they mutate state or reach
// secrets but are a step below outright command execution. Rendered amber.
var writeCapabilities = map[CapabilityTag]bool{
	CapFileWrite:     true,
	CapDatabaseWrite: true,
	CapGitPush:       true,
	CapReadSecret:    true,
}

// egressCapabilities are the read/egress tier: they read data or reach the
// network, the raw material of an exfiltration chain. Rendered pale yellow.
var egressCapabilities = map[CapabilityTag]bool{
	CapFileRead:    true,
	CapHTTPRequest: true,
	CapEmailSend:   true,
	CapWebhookPost: true,
}

// Graphviz fill colours per risk tier. Kept as named constants so the mapping
// from risk to colour is stated once.
const (
	colorDanger  = "#ffcccc"
	colorWrite   = "#ffe0b3"
	colorEgress  = "#fff5cc"
	colorNeutral = "#e8f4ff"
)

// CapabilityColor returns the Graphviz fill colour for the strongest capability
// in caps. The tiers are checked most-dangerous first, so a tool that can both
// read a file and exec a shell is coloured for the shell.
func CapabilityColor(caps []string) string {
	if anyCapIn(caps, dangerCapabilities) {
		return colorDanger
	}
	if anyCapIn(caps, writeCapabilities) {
		return colorWrite
	}
	if anyCapIn(caps, egressCapabilities) {
		return colorEgress
	}
	return colorNeutral
}

// anyCapIn reports whether any capability string is in the given tier.
func anyCapIn(caps []string, tier map[CapabilityTag]bool) bool {
	for _, c := range caps {
		if tier[CapabilityTag(c)] {
			return true
		}
	}
	return false
}

// capabilityLabel joins a tool's capabilities into a stable, sorted label, or
// "" when it has none.
func capabilityLabel(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	cp := make([]string, len(caps))
	copy(cp, caps)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// sanitizeGraphLabel neutralises characters that would break a Mermaid or
// Graphviz label. An unsanitised agent or tool name with a quote or bracket
// produces malformed output — which is exactly the bug the un-sanitising copy
// carried.
func sanitizeGraphLabel(s string) string {
	return strings.NewReplacer("\"", "'", "\n", " ", "[", "(", "]", ")").Replace(s)
}

// RenderMermaid renders the agent capability lattice as a Mermaid graph, one
// subgraph per agent. An inventory with no tool registrations renders an
// explicit empty node rather than an empty graph, so a consumer can tell "no
// agents detected" from "rendering failed".
func RenderMermaid(inv *Inventory) string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	if inv == nil || len(inv.ToolMatrix) == 0 {
		b.WriteString("    empty[\"No agent tool registrations detected\"]\n")
		return b.String()
	}
	for i, set := range inv.ToolMatrix {
		fmt.Fprintf(&b, "    subgraph agent%d [%s]\n", i, sanitizeGraphLabel(set.Agent))
		for j, tool := range set.Tools {
			label := sanitizeGraphLabel(tool)
			if caps := capabilityLabel(set.Capabilities[tool]); caps != "" {
				label += "<br/><small>" + caps + "</small>"
			}
			fmt.Fprintf(&b, "        a%d_t%d[\"%s\"]\n", i, j, label)
		}
		b.WriteString("    end\n")
	}
	return b.String()
}

// RenderDot renders the agent capability lattice as Graphviz dot, one cluster
// per agent, each tool filled by the risk colour of its strongest capability.
func RenderDot(inv *Inventory) string {
	var b strings.Builder
	b.WriteString("digraph nox_agent_lattice {\n")
	b.WriteString("    rankdir=LR;\n")
	b.WriteString("    node [shape=box, style=rounded];\n")
	if inv != nil {
		for i, set := range inv.ToolMatrix {
			fmt.Fprintf(&b, "    subgraph cluster_%d {\n", i)
			fmt.Fprintf(&b, "        label=%q;\n", sanitizeGraphLabel(set.Agent))
			for j, tool := range set.Tools {
				label := tool
				if caps := capabilityLabel(set.Capabilities[tool]); caps != "" {
					label = tool + "\\n[" + caps + "]"
				}
				color := CapabilityColor(set.Capabilities[tool])
				fmt.Fprintf(&b, "        a%d_t%d [label=%q, fillcolor=%q, style=\"rounded,filled\"];\n", i, j, label, color)
			}
			b.WriteString("    }\n")
		}
	}
	b.WriteString("}\n")
	return b.String()
}
