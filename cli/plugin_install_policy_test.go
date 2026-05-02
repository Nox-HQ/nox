package main

import (
	"testing"

	"github.com/nox-hq/nox/registry/trust"
)

func TestResolveTrustPolicy_AllowUnverifiedWins(t *testing.T) {
	if got := resolveTrustPolicy("enterprise", true, true, true); got != "permissive" {
		t.Errorf("--allow-unverified should override everything; got %q", got)
	}
}

func TestResolveTrustPolicy_RequireVerifiedBeatsRequireSignature(t *testing.T) {
	if got := resolveTrustPolicy("", true, true, false); got != "enterprise" {
		t.Errorf("--require-verified should win over --require-signature; got %q", got)
	}
}

func TestResolveTrustPolicy_RequireSignature(t *testing.T) {
	if got := resolveTrustPolicy("", false, true, false); got != "default" {
		t.Errorf("--require-signature -> default policy; got %q", got)
	}
}

func TestResolveTrustPolicy_FallthroughDefault(t *testing.T) {
	// Fall-through ramp (Phase 10 / Cosign-keyless GA): every official
	// plugin in the registry now ships cosign-signed; the install
	// path promotes a passing cosign verify to TrustCommunity, which
	// satisfies the default policy without operator intervention.
	if got := resolveTrustPolicy("", false, false, false); got != "default" {
		t.Errorf("with no flags or .nox.yaml in cwd, got %q (expected default — cosign-signed plugins now satisfy this)", got)
	}
}

func TestPolicyFromName(t *testing.T) {
	cases := map[string]trust.Level{
		"permissive": trust.TrustUnverified,
		"default":    trust.TrustCommunity,
		"enterprise": trust.TrustVerified,
		// Empty / unknown names ramp to default policy alongside the
		// fall-through above.
		"":     trust.TrustCommunity,
		"junk": trust.TrustCommunity,
	}
	for name, wantMin := range cases {
		got := policyFromName(name)
		if got.MinLevel != wantMin {
			t.Errorf("policyFromName(%q).MinLevel = %v, want %v", name, got.MinLevel, wantMin)
		}
	}
}
