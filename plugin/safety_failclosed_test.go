package plugin

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// TestValidateManifest_RiskClassFailClosed asserts the policy gate FAILS CLOSED:
// a risk_class the host does not recognise must be rejected, not admitted.
//
// Regression guard for the fail-open defect where riskClassLevel returned -1 for
// unrecognised values and `-1 > 0` is false, so "RUNTIME", "exec", "active "
// (trailing space) etc. slipped past a passive ceiling.
func TestValidateManifest_RiskClassFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		maxPolicy RiskClass
		wantViolN int
	}{
		// Canonical value that genuinely exceeds the ceiling: blocked.
		{name: "canonical runtime exceeds passive", requested: "runtime", maxPolicy: RiskClassPassive, wantViolN: 1},
		// Non-canonical values that must ALSO be blocked (fail closed).
		{name: "uppercase RUNTIME", requested: "RUNTIME", maxPolicy: RiskClassPassive, wantViolN: 1},
		{name: "uppercase ACTIVE", requested: "ACTIVE", maxPolicy: RiskClassPassive, wantViolN: 1},
		{name: "exec alias", requested: "exec", maxPolicy: RiskClassPassive, wantViolN: 1},
		{name: "root alias", requested: "root", maxPolicy: RiskClassPassive, wantViolN: 1},
		{name: "dangerous alias", requested: "dangerous", maxPolicy: RiskClassPassive, wantViolN: 1},
		{name: "trailing space active", requested: "active ", maxPolicy: RiskClassPassive, wantViolN: 1},
		// Unknown value even under a permissive ceiling: still rejected, because the
		// host cannot reason about a class it does not know.
		{name: "unknown under runtime ceiling", requested: "banana", maxPolicy: RiskClassRuntime, wantViolN: 1},
		// Empty stays a legitimate "unset -> default" case: not a violation.
		{name: "empty passes", requested: "", maxPolicy: RiskClassPassive, wantViolN: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{RiskClass: tt.requested},
			}
			policy := DefaultPolicy()
			policy.MaxRiskClass = tt.maxPolicy

			violations := ValidateManifest(manifest, &policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("ValidateManifest risk_class=%q max=%q: got %d violations, want %d: %v",
					tt.requested, tt.maxPolicy, len(violations), tt.wantViolN, violations)
			}
		})
	}
}

// TestValidateToolInvocation_RiskClassFailClosed exercises the same fail-closed
// requirement on the per-tool invocation path, which is the check that actually
// constrains what runs at call time.
func TestValidateToolInvocation_RiskClassFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		wantViolN int
	}{
		{name: "canonical runtime blocked", requested: "runtime", wantViolN: 1},
		{name: "uppercase RUNTIME blocked", requested: "RUNTIME", wantViolN: 1},
		{name: "exec alias blocked", requested: "exec", wantViolN: 1},
		{name: "trailing space blocked", requested: "active ", wantViolN: 1},
		{name: "empty allowed", requested: "", wantViolN: 0},
		{name: "passive allowed", requested: "passive", wantViolN: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Capabilities: []*pluginv1.Capability{{
					Tools: []*pluginv1.ToolDef{{
						Name:   "analyze",
						Safety: &pluginv1.SafetyRequirements{RiskClass: tt.requested},
					}},
				}},
			}
			policy := DefaultPolicy() // passive ceiling

			violations := ValidateToolInvocation(manifest, "analyze", &policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("ValidateToolInvocation risk_class=%q: got %d violations, want %d: %v",
					tt.requested, len(violations), tt.wantViolN, violations)
			}
		})
	}
}
