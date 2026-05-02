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

func TestResolveTrustPolicy_FallthroughPermissive(t *testing.T) {
	if got := resolveTrustPolicy("", false, false, false); got != "permissive" {
		t.Errorf("with no flags or .nox.yaml in cwd, got %q", got)
	}
}

func TestPolicyFromName(t *testing.T) {
	cases := map[string]trust.Level{
		"permissive": trust.TrustUnverified,
		"default":    trust.TrustCommunity,
		"enterprise": trust.TrustVerified,
		"":           trust.TrustUnverified,
		"junk":       trust.TrustUnverified,
	}
	for name, wantMin := range cases {
		got := policyFromName(name)
		if got.MinLevel != wantMin {
			t.Errorf("policyFromName(%q).MinLevel = %v, want %v", name, got.MinLevel, wantMin)
		}
	}
}
