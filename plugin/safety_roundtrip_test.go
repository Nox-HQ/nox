package plugin

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// RegisterPlugin/RegisterBinary do not validate the manifest the plugin sent.
// They convert it to Info, then rebuild a manifest from that Info via
// infoToProtoCapabilities and validate the rebuilt copy. Any field dropped in
// that round trip is invisible to validation.
//
// Per-tool safety was dropped exactly there: it was read into ToolInfo but not
// written back out, so registration silently fell back to judging the
// plugin-level ceiling alone — the behaviour per-tool safety exists to replace.
// Unit tests that call ValidateManifest with a hand-built proto cannot catch
// this, because they never traverse the conversion. This test does.
func TestInfoRoundTripPreservesPerToolSafety(t *testing.T) {
	toolSafety := &pluginv1.SafetyRequirements{RiskClass: "passive"}
	info := Info{
		Name: "nox/example",
		Capabilities: []CapabilityInfo{{
			Name: "example",
			Tools: []ToolInfo{
				{Name: "analyze", ReadOnly: true, Safety: toolSafety},
				{Name: "validate", ReadOnly: false}, // inherits the ceiling
			},
		}},
		Safety: &pluginv1.SafetyRequirements{
			RiskClass:         "active",
			NeedsConfirmation: true,
			NetworkHosts:      []string{"*"},
		},
	}

	caps := infoToProtoCapabilities(&info)
	if len(caps) != 1 || len(caps[0].GetTools()) != 2 {
		t.Fatalf("unexpected capability shape: %+v", caps)
	}
	if got := caps[0].GetTools()[0].GetSafety(); got == nil {
		t.Fatal("per-tool safety lost in the Info round trip — registration would fall back to the plugin ceiling")
	} else if got.GetRiskClass() != "passive" {
		t.Fatalf("per-tool risk class = %q, want passive", got.GetRiskClass())
	}
	if caps[0].GetTools()[1].GetSafety() != nil {
		t.Error("tool without its own safety must round-trip as nil so it inherits the ceiling")
	}

	// The behaviour that actually matters: a passive policy must admit this
	// plugin, because `analyze` is usable even though the ceiling is not.
	rebuilt := &pluginv1.GetManifestResponse{
		Name:         info.Name,
		Capabilities: caps,
		Safety:       info.Safety,
	}
	if v := ValidateManifest(rebuilt, &Policy{MaxRiskClass: RiskClassPassive}); len(v) != 0 {
		t.Fatalf("registration rejected a plugin with a usable passive tool: %v", v)
	}
}
