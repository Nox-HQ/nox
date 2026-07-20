package main

import (
	"testing"

	"github.com/nox-hq/nox/registry/trust"
)

// trustViolationsBlock is the single gate both `nox plugin install` and
// `nox plugin update` use to enforce the trust policy on a fetched artifact.
// Store.Fetch is fail-open (returns a runnable binary even for a policy-failing
// artifact), so this predicate is the actual enforcement; the update path
// silently skipped it before, installing unverified plugins. The matrix below
// pins the decision so the two paths cannot diverge again.
func TestTrustViolationsBlock(t *testing.T) {
	twoViolations := trust.VerifyResult{Violations: []trust.Violation{
		{Field: "trust_level", Message: `trust level "unverified" is below minimum "community"`},
		{Field: "signature", Message: "no signature present"},
	}}
	none := trust.VerifyResult{}

	cases := []struct {
		name            string
		vr              trust.VerifyResult
		policy          string
		allowUnverified bool
		wantFatal       bool
		wantMsgs        int
	}{
		{"clean artifact passes", none, "default", false, false, 0},
		{"violations blocked under default", twoViolations, "default", false, true, 2},
		{"violations blocked under enterprise", twoViolations, "enterprise", false, true, 2},
		{"permissive policy never fatal", twoViolations, "permissive", false, false, 2},
		{"allow-unverified overrides", twoViolations, "default", true, false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, fatal := trustViolationsBlock(tc.vr, tc.policy, tc.allowUnverified)
			if fatal != tc.wantFatal {
				t.Errorf("fatal = %v, want %v", fatal, tc.wantFatal)
			}
			if len(msgs) != tc.wantMsgs {
				t.Errorf("len(msgs) = %d, want %d", len(msgs), tc.wantMsgs)
			}
		})
	}
}
