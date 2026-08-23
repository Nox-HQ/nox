package ai

import (
	"strings"
	"testing"
)

// The risk colouring is a security judgment, and the whole reason it moved into
// the domain is that it must weigh risk the same everywhere. Pin the tiers so a
// future edit that, say, quietly demotes shell_exec fails here.
func TestCapabilityColorRiskTiers(t *testing.T) {
	tests := []struct {
		name string
		caps []string
		want string
	}{
		{"none", nil, colorNeutral},
		{"read only", []string{string(CapFileRead)}, colorEgress},
		{"network egress", []string{string(CapHTTPRequest)}, colorEgress},
		{"write", []string{string(CapFileWrite)}, colorWrite},
		{"secret read is write-tier", []string{string(CapReadSecret)}, colorWrite},
		{"shell exec is danger", []string{string(CapShellExec)}, colorDanger},
		{"payment is danger", []string{string(CapPaymentInitiate)}, colorDanger},
		// The strongest capability wins: a tool that reads a file AND execs a
		// shell is coloured for the shell, not the read.
		{"strongest wins", []string{string(CapFileRead), string(CapShellExec)}, colorDanger},
		{"write plus egress -> write", []string{string(CapHTTPRequest), string(CapFileWrite)}, colorWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CapabilityColor(tt.caps); got != tt.want {
				t.Errorf("CapabilityColor(%v) = %s, want %s", tt.caps, got, tt.want)
			}
		})
	}
}

// The empty inventory must render an explicit "none detected" node, so a
// consumer can tell it from a render that failed — the case the drifted server
// copy had lost.
func TestRenderMermaidEmptyInventory(t *testing.T) {
	for _, inv := range []*Inventory{nil, {}} {
		got := RenderMermaid(inv)
		if !strings.Contains(got, "No agent tool registrations detected") {
			t.Errorf("empty inventory should render an explicit empty node, got %q", got)
		}
	}
}

// Labels with graph-breaking characters must be sanitised in both formats — the
// other drift the un-sanitising copy carried.
func TestRenderSanitizesLabels(t *testing.T) {
	inv := &Inventory{ToolMatrix: []ToolPermissionSet{{
		Agent: `agent "x" [danger]`,
		Tools: []string{`tool "y"`},
	}}}
	m := RenderMermaid(inv)
	if strings.Contains(m, `"x"`) || strings.Contains(m, "[danger]") {
		t.Errorf("mermaid did not sanitise the agent label: %q", m)
	}
	d := RenderDot(inv)
	if strings.Contains(d, "[danger]") {
		t.Errorf("dot did not sanitise the agent label: %q", d)
	}
}

// The dot renderer must actually emit the risk colour, so the security signal
// reaches the rendered graph — the feature the server copy had dropped entirely.
func TestRenderDotEmitsRiskColor(t *testing.T) {
	inv := &Inventory{ToolMatrix: []ToolPermissionSet{{
		Agent:        "a",
		Tools:        []string{"run"},
		Capabilities: map[string][]string{"run": {string(CapShellExec)}},
	}}}
	d := RenderDot(inv)
	if !strings.Contains(d, colorDanger) {
		t.Errorf("dot must fill a shell_exec tool with the danger colour %s, got %q", colorDanger, d)
	}
}
