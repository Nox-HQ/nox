package plugin

import (
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
)

func TestProfileForTrackAllTracks(t *testing.T) {
	for _, track := range registry.AllTracks() {
		p := ProfileForTrack(track)
		if p.MaxRiskClass == "" {
			t.Errorf("ProfileForTrack(%q): MaxRiskClass is empty", track)
		}
		if p.ToolInvocationTimeout <= 0 {
			t.Errorf("ProfileForTrack(%q): ToolInvocationTimeout is %v", track, p.ToolInvocationTimeout)
		}
		if p.MaxArtifactBytes <= 0 {
			t.Errorf("ProfileForTrack(%q): MaxArtifactBytes is %d", track, p.MaxArtifactBytes)
		}
	}
}

func TestProfileForTrackPassiveTracks(t *testing.T) {
	passiveTracks := []registry.Track{
		registry.TrackCoreAnalysis,
		registry.TrackAISecurity,
		registry.TrackThreatModeling,
		registry.TrackPolicyGovernance,
		registry.TrackIncidentReadiness,
		registry.TrackDeveloperExperience,
	}

	for _, track := range passiveTracks {
		p := ProfileForTrack(track)
		if p.MaxRiskClass != RiskClassPassive {
			t.Errorf("ProfileForTrack(%q): expected passive, got %q", track, p.MaxRiskClass)
		}
	}
}

func TestProfileForTrackDynamicRuntime(t *testing.T) {
	p := ProfileForTrack(registry.TrackDynamicRuntime)
	if p.MaxRiskClass != RiskClassActive {
		t.Errorf("dynamic-runtime: expected active, got %q", p.MaxRiskClass)
	}
	if !p.AllowConfirmationReqd {
		t.Error("dynamic-runtime: should allow confirmation")
	}
	if len(p.AllowedNetworkHosts) == 0 {
		t.Error("dynamic-runtime: should have allowed network hosts")
	}
}

func TestProfileForTrackSupplyChain(t *testing.T) {
	p := ProfileForTrack(registry.TrackSupplyChain)
	if len(p.AllowedNetworkHosts) == 0 {
		t.Error("supply-chain: should have allowed network hosts for OSV/npm/etc")
	}
}

func TestProfileForTrackAgentAssistance(t *testing.T) {
	p := ProfileForTrack(registry.TrackAgentAssistance)
	if len(p.AllowedNetworkHosts) == 0 {
		t.Error("agent-assistance: should have allowed network hosts for LLM APIs")
	}
	if len(p.AllowedEnvVars) == 0 {
		t.Error("agent-assistance: should allow API key env vars")
	}
}

func TestProfileForTrackUnknown(t *testing.T) {
	p := ProfileForTrack("nonexistent")
	def := DefaultPolicy()
	if p.MaxRiskClass != def.MaxRiskClass {
		t.Errorf("unknown track: expected default policy risk class %q, got %q", def.MaxRiskClass, p.MaxRiskClass)
	}
}

func TestMergeWithUserPolicyOverrides(t *testing.T) {
	profile := ProfileForTrack(registry.TrackCoreAnalysis)
	user := Policy{
		MaxConcurrency:        8,
		ToolInvocationTimeout: 5 * time.Minute,
	}

	merged := MergeWithUserPolicy(profile, user)

	if merged.MaxConcurrency != 8 {
		t.Errorf("merged concurrency = %d, want 8", merged.MaxConcurrency)
	}
	if merged.ToolInvocationTimeout != 5*time.Minute {
		t.Errorf("merged timeout = %v, want 5m", merged.ToolInvocationTimeout)
	}
	// Non-overridden fields should keep profile defaults.
	if merged.MaxRiskClass != RiskClassPassive {
		t.Errorf("merged risk class = %q, want passive", merged.MaxRiskClass)
	}
	if merged.MaxArtifactBytes != profile.MaxArtifactBytes {
		t.Errorf("merged artifact bytes = %d, want %d", merged.MaxArtifactBytes, profile.MaxArtifactBytes)
	}
}

func TestMergeWithUserPolicyNoOverrides(t *testing.T) {
	profile := ProfileForTrack(registry.TrackAISecurity)
	empty := Policy{}

	merged := MergeWithUserPolicy(profile, empty)

	if merged.MaxRiskClass != profile.MaxRiskClass {
		t.Errorf("risk class changed from %q to %q", profile.MaxRiskClass, merged.MaxRiskClass)
	}
	if merged.MaxConcurrency != profile.MaxConcurrency {
		t.Errorf("concurrency changed from %d to %d", profile.MaxConcurrency, merged.MaxConcurrency)
	}
}

func TestMergeWithUserPolicyRiskClassEscalation(t *testing.T) {
	profile := ProfileForTrack(registry.TrackCoreAnalysis)
	user := Policy{
		MaxRiskClass: RiskClassActive,
	}

	merged := MergeWithUserPolicy(profile, user)

	// User can escalate risk class if they want.
	if merged.MaxRiskClass != RiskClassActive {
		t.Errorf("merged risk class = %q, want active", merged.MaxRiskClass)
	}
}

func TestMergeWithUserPolicyNetworkOverride(t *testing.T) {
	profile := ProfileForTrack(registry.TrackSupplyChain)
	user := Policy{
		AllowedNetworkHosts: []string{"custom.registry.example.com"},
	}

	merged := MergeWithUserPolicy(profile, user)

	if len(merged.AllowedNetworkHosts) != 1 || merged.AllowedNetworkHosts[0] != "custom.registry.example.com" {
		t.Errorf("merged network hosts = %v, want [custom.registry.example.com]", merged.AllowedNetworkHosts)
	}
}
