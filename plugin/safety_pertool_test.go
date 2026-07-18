package plugin

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// The shape that motivated per-tool safety: one plugin, one passive tool, one
// active tool. Before ToolDef.safety the plugin could only declare the union,
// so the active tool gated the passive one.
func mixedManifest() *pluginv1.GetManifestResponse {
	return &pluginv1.GetManifestResponse{
		Safety: &pluginv1.SafetyRequirements{
			RiskClass:         "active",
			NeedsConfirmation: true,
			NetworkHosts:      []string{"*"},
		},
		Capabilities: []*pluginv1.Capability{{
			Name: "red-team",
			Tools: []*pluginv1.ToolDef{
				{
					Name:     "analyze",
					ReadOnly: true,
					Safety:   &pluginv1.SafetyRequirements{RiskClass: "passive"},
				},
				{
					Name:     "validate",
					ReadOnly: false,
					Safety: &pluginv1.SafetyRequirements{
						RiskClass:         "active",
						NeedsConfirmation: true,
						NetworkHosts:      []string{"*"},
					},
				},
				// No Safety block: must inherit the plugin-level ceiling, which
				// is how every plugin behaved before this field existed.
				{Name: "legacy", ReadOnly: true},
			},
		}},
	}
}

func passivePolicy() *Policy {
	return &Policy{MaxRiskClass: RiskClassPassive}
}

func TestValidateManifest_AdmitsPluginWhenSomeToolIsUsable(t *testing.T) {
	// The ceiling (active + "*" + confirmation) exceeds a passive policy, but
	// `analyze` is admissible, so the plugin must register rather than be
	// rejected outright — that rejection was the bug.
	if v := ValidateManifest(mixedManifest(), passivePolicy()); len(v) != 0 {
		t.Fatalf("expected registration to succeed, got violations: %v", v)
	}
}

func TestValidateManifest_StillRejectsWhenNoToolIsUsable(t *testing.T) {
	m := mixedManifest()
	// Drop the one admissible tool; nothing usable remains.
	m.Capabilities[0].Tools = m.Capabilities[0].Tools[1:]
	if v := ValidateManifest(m, passivePolicy()); len(v) == 0 {
		t.Fatal("expected rejection when no tool is admissible")
	}
}

func TestValidateToolInvocation_EnforcesPerToolRequirements(t *testing.T) {
	m, pol := mixedManifest(), passivePolicy()

	if v := ValidateToolInvocation(m, "analyze", pol); len(v) != 0 {
		t.Errorf("passive tool should be allowed under a passive policy, got %v", v)
	}
	if v := ValidateToolInvocation(m, "validate", pol); len(v) == 0 {
		t.Error("active tool must be refused under a passive policy")
	}
	// Inheritance: no per-tool block => the plugin ceiling applies.
	if v := ValidateToolInvocation(m, "legacy", pol); len(v) == 0 {
		t.Error("tool without its own safety must inherit the plugin ceiling")
	}
	// Fail closed on an unknown name rather than silently passing.
	if v := ValidateToolInvocation(m, "no-such-tool", pol); len(v) == 0 {
		t.Error("unknown tool must be refused, not allowed through unvalidated")
	}
}

func TestValidateToolInvocation_PermissivePolicyAllowsEverything(t *testing.T) {
	pol := &Policy{
		MaxRiskClass:          RiskClassActive,
		AllowConfirmationReqd: true,
		AllowedNetworkHosts:   []string{"*"},
	}
	for _, name := range []string{"analyze", "validate", "legacy"} {
		if v := ValidateToolInvocation(mixedManifest(), name, pol); len(v) != 0 {
			t.Errorf("tool %q refused under permissive policy: %v", name, v)
		}
	}
}

// read_only does NOT imply passive: nox/llm-triage ships a read_only tool that
// sends source to an external endpoint. Inferring passiveness from read_only
// would grant egress to exactly the tool that exfiltrates source, so the two
// checks must stay independent.
func TestReadOnlyDoesNotImplyPassive(t *testing.T) {
	m := &pluginv1.GetManifestResponse{
		Safety: &pluginv1.SafetyRequirements{RiskClass: "active"},
		Capabilities: []*pluginv1.Capability{{
			Name: "triage",
			Tools: []*pluginv1.ToolDef{{
				Name:     "llm_triage",
				ReadOnly: true, // read-only, yet egresses source code
				Safety: &pluginv1.SafetyRequirements{
					RiskClass:         "active",
					NeedsConfirmation: true,
					NetworkHosts:      []string{"*"},
				},
			}},
		}},
	}
	if v := ValidateToolInvocation(m, "llm_triage", passivePolicy()); len(v) == 0 {
		t.Fatal("a read_only tool that egresses must still be refused by a passive policy")
	}
}
