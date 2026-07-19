package plugin

import (
	"testing"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
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

	merged := MergeWithUserPolicy(&profile, &user)

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

	merged := MergeWithUserPolicy(&profile, &empty)

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

	merged := MergeWithUserPolicy(&profile, &user)

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

	merged := MergeWithUserPolicy(&profile, &user)

	if len(merged.AllowedNetworkHosts) != 1 || merged.AllowedNetworkHosts[0] != "custom.registry.example.com" {
		t.Errorf("merged network hosts = %v, want [custom.registry.example.com]", merged.AllowedNetworkHosts)
	}
}

// --- track profile enforcement ---

// TestHost_AppliesTrackProfile confirms the profile actually reaches the
// enforced policy. Track profiles existed for several releases while the host
// enforced DefaultPolicy() regardless, so docs promised a sandbox shape that
// was never applied.
func TestHost_AppliesTrackProfile(t *testing.T) {
	t.Parallel()

	h := NewHost()
	got := h.policyForTrack(registry.TrackDynamicRuntime)

	if got.MaxRiskClass != RiskClassActive {
		t.Errorf("MaxRiskClass = %q, want %q", got.MaxRiskClass, RiskClassActive)
	}
	if len(got.AllowedNetworkHosts) == 0 {
		t.Error("expected the dynamic-runtime profile to permit localhost")
	}
}

// TestHost_UnknownTrackFallsBackToStrict is the security-critical case: a
// plugin whose provenance cannot be established must not get a profile.
// Sideloaded (--local) binaries and installs predating track recording both
// arrive with an empty track.
func TestHost_UnknownTrackFallsBackToStrict(t *testing.T) {
	t.Parallel()

	h := NewHost()

	for _, track := range []registry.Track{"", "not-a-real-track", "dynamic-runtime-ish"} {
		t.Run(string(track), func(t *testing.T) {
			got := h.policyForTrack(track)

			if got.MaxRiskClass != RiskClassPassive {
				t.Errorf("MaxRiskClass = %q, want passive for an unverifiable track", got.MaxRiskClass)
			}
			if len(got.AllowedNetworkHosts) != 0 {
				t.Errorf("an unverifiable track was granted network access: %v", got.AllowedNetworkHosts)
			}
		})
	}
}

// TestHost_IgnoreTrackProfilesRestoresStrictBase covers the opt-out. It has to
// exist because the override semantics are one-directional: an operator can
// widen an allowlist but cannot empty one, so without this flag there is no way
// to revoke the localhost access the dynamic-runtime profile grants.
func TestHost_IgnoreTrackProfilesRestoresStrictBase(t *testing.T) {
	t.Parallel()

	h := NewHost(WithIgnoreTrackProfiles(true))
	got := h.policyForTrack(registry.TrackDynamicRuntime)

	if got.MaxRiskClass != RiskClassPassive {
		t.Errorf("MaxRiskClass = %q, want passive when track profiles are ignored", got.MaxRiskClass)
	}
	if len(got.AllowedNetworkHosts) != 0 {
		t.Errorf("expected no network access when track profiles are ignored, got %v", got.AllowedNetworkHosts)
	}
}

// TestEffectivePolicy_OperatorOverridesWin confirms a project can still tighten
// or widen what its own plugins get; the track sets the base, not the ceiling.
func TestEffectivePolicy_OperatorOverridesWin(t *testing.T) {
	t.Parallel()

	overrides := Policy{
		MaxRiskClass:        RiskClassPassive,
		AllowedNetworkHosts: []string{"proxy.internal"},
	}
	got := EffectivePolicy(registry.TrackDynamicRuntime, &overrides, false)

	if got.MaxRiskClass != RiskClassPassive {
		t.Errorf("operator's max_risk_class was not honoured: got %q", got.MaxRiskClass)
	}
	if len(got.AllowedNetworkHosts) != 1 || got.AllowedNetworkHosts[0] != "proxy.internal" {
		t.Errorf("operator's network allowlist was not honoured: got %v", got.AllowedNetworkHosts)
	}
}

// TestEffectivePolicy_ProfileAppliesWithoutOverrides pins the loosening this
// change deliberately introduces, so it cannot happen by accident later.
func TestEffectivePolicy_ProfileAppliesWithoutOverrides(t *testing.T) {
	t.Parallel()

	got := EffectivePolicy(registry.TrackDynamicRuntime, &Policy{}, false)

	if got.MaxRiskClass != RiskClassActive {
		t.Errorf("MaxRiskClass = %q, want active from the track profile", got.MaxRiskClass)
	}
	if len(got.AllowedNetworkHosts) == 0 {
		t.Error("expected localhost access from the track profile")
	}
}

// TestTrackProfile_GovernsManifestAcceptance exercises the decision that
// actually matters: whether a plugin declaring network access is admitted.
//
// It runs the real ValidateManifest against the real resolved policies, so it
// would catch a regression where policyForTrack returns the right values but
// registration consults something else.
func TestTrackProfile_GovernsManifestAcceptance(t *testing.T) {
	t.Parallel()

	// A plugin that needs localhost — the shape a dynamic-runtime scanner has.
	manifest := &pluginv1.GetManifestResponse{
		Name:       "runtime-scanner",
		Version:    "1.0.0",
		ApiVersion: HostAPIVersion,
		Safety: &pluginv1.SafetyRequirements{
			RiskClass:    "active",
			NetworkHosts: []string{"localhost"},
		},
	}

	h := NewHost()

	t.Run("dynamic-runtime track admits it", func(t *testing.T) {
		policy := h.policyForTrack(registry.TrackDynamicRuntime)
		if v := ValidateManifest(manifest, &policy); len(v) > 0 {
			t.Errorf("expected admission under the dynamic-runtime profile, rejected with: %v", v)
		}
	})

	t.Run("core-analysis track rejects it", func(t *testing.T) {
		// Same host, same process, different plugin: policy is per-plugin, so a
		// dynamic-runtime plugin's grant must not leak to a passive track.
		policy := h.policyForTrack(registry.TrackCoreAnalysis)
		if v := ValidateManifest(manifest, &policy); len(v) == 0 {
			t.Error("expected rejection under the core-analysis profile, but it was admitted")
		}
	})

	t.Run("unknown track rejects it", func(t *testing.T) {
		policy := h.policyForTrack("")
		if v := ValidateManifest(manifest, &policy); len(v) == 0 {
			t.Error("a plugin of unverifiable provenance was admitted with network access")
		}
	})

	t.Run("ignore_track_profiles rejects it", func(t *testing.T) {
		strict := NewHost(WithIgnoreTrackProfiles(true))
		policy := strict.policyForTrack(registry.TrackDynamicRuntime)
		if v := ValidateManifest(manifest, &policy); len(v) == 0 {
			t.Error("the opt-out did not restore strict enforcement")
		}
	})
}
