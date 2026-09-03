package main

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/plugin"
)

func info(name string, tools ...plugin.ToolInfo) plugin.Info {
	return plugin.Info{Name: name, Capabilities: []plugin.CapabilityInfo{{Tools: tools}}}
}

// A plugin listed in plugins.required that exposes neither a "scan" tool nor a
// post-scan one registers, is counted, and is never invoked. Before this, the
// scan said nothing at all: the operator declared a detector, the scan reported
// no problem with it, and it contributed nothing.
//
// Two real examples from the published registry: nox/red-team provides
// analyze/validate, nox/grc provides assess/gap_report/evidence. Both are
// invoked explicitly with `nox plugin call`, which is a fine design — the
// defect was that a scan could not tell you that was what you had.
func TestPluginWithNoInvocableToolIsDegraded(t *testing.T) {
	got := uninvocableDegradations([]plugin.Info{
		info("nox/red-team",
			plugin.ToolInfo{Name: "analyze"},
			plugin.ToolInfo{Name: "validate"},
		),
	})

	if len(got) != 1 {
		t.Fatalf("degradations = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Detail, "nox/red-team") {
		t.Errorf("detail does not name the plugin: %q", got[0].Detail)
	}
	// The operator needs to know which tools it does have, or the report is a
	// dead end rather than an instruction.
	for _, want := range []string{"analyze", "validate"} {
		if !strings.Contains(got[0].Detail, want) {
			t.Errorf("detail omits tool %q: %q", want, got[0].Detail)
		}
	}
	if !strings.Contains(got[0].Impact, "nox plugin call") {
		t.Errorf("impact does not say how to invoke it: %q", got[0].Impact)
	}
}

// Both invocation paths count. Reporting a plugin that only enriches would be
// a false alarm on exactly the plugins that work.
func TestInvocablePluginsAreNotDegraded(t *testing.T) {
	got := uninvocableDegradations([]plugin.Info{
		info("nox/api-abuse", plugin.ToolInfo{Name: "scan"}),
		info("nox/threat-enrich", plugin.ToolInfo{Name: "enrich", RequiresScanContext: true}),
		info("nox/risk-score",
			plugin.ToolInfo{Name: "enrich_findings", RequiresScanContext: true},
			plugin.ToolInfo{Name: "get_epss"},
			plugin.ToolInfo{Name: "get_kev_status"},
		),
	})

	if len(got) != 0 {
		t.Errorf("degradations = %v, want none", got)
	}
}

// A plugin that registers with no tools at all is inert for the same reason
// and must not produce a detail claiming it provides an empty list.
func TestPluginWithNoToolsIsDegradedWithoutAToolList(t *testing.T) {
	got := uninvocableDegradations([]plugin.Info{{Name: "nox/empty"}})

	if len(got) != 1 {
		t.Fatalf("degradations = %d, want 1", len(got))
	}
	if strings.Contains(got[0].Detail, "it provides") {
		t.Errorf("detail claims a tool list it does not have: %q", got[0].Detail)
	}
}
