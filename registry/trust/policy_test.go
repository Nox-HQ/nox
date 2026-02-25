package trust

import "testing"

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.MinLevel != TrustCommunity {
		t.Errorf("MinLevel = %v, want %v", p.MinLevel, TrustCommunity)
	}
	if !p.RequireDigest {
		t.Error("RequireDigest should be true")
	}
	if len(p.AllowedAPIVersions) != 1 || p.AllowedAPIVersions[0] != "v1" {
		t.Errorf("AllowedAPIVersions = %v, want [v1]", p.AllowedAPIVersions)
	}
}

func TestEnterprisePolicy(t *testing.T) {
	p := EnterprisePolicy()
	if p.MinLevel != TrustVerified {
		t.Errorf("MinLevel = %v, want %v", p.MinLevel, TrustVerified)
	}
	if !p.RequireDigest {
		t.Error("RequireDigest should be true")
	}
}

func TestPermissivePolicy(t *testing.T) {
	p := PermissivePolicy()
	if p.MinLevel != TrustUnverified {
		t.Errorf("MinLevel = %v, want %v", p.MinLevel, TrustUnverified)
	}
	if p.RequireDigest {
		t.Error("RequireDigest should be false")
	}
}

func TestCheckAPIVersion(t *testing.T) {
	tests := []struct {
		name           string
		policy         Policy
		apiVersion     string
		wantViolations int
	}{
		{
			name:           "allowed version",
			policy:         DefaultPolicy(),
			apiVersion:     "v1",
			wantViolations: 0,
		},
		{
			name:           "disallowed version",
			policy:         DefaultPolicy(),
			apiVersion:     "v2",
			wantViolations: 1,
		},
		{
			name:           "empty version",
			policy:         DefaultPolicy(),
			apiVersion:     "",
			wantViolations: 1,
		},
		{
			name: "multiple allowed versions",
			policy: Policy{
				AllowedAPIVersions: []string{"v1", "v2"},
			},
			apiVersion:     "v2",
			wantViolations: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := tt.policy.CheckAPIVersion(tt.apiVersion)
			if len(violations) != tt.wantViolations {
				t.Errorf("CheckAPIVersion(%q) returned %d violations, want %d: %v",
					tt.apiVersion, len(violations), tt.wantViolations, violations)
			}
		})
	}
}

func TestEnforce(t *testing.T) {
	tests := []struct {
		name           string
		policy         Policy
		result         VerifyResult
		wantViolations int
	}{
		{
			name:   "verified meets default policy",
			policy: DefaultPolicy(),
			result: VerifyResult{
				Level:       TrustVerified,
				DigestMatch: true,
			},
			wantViolations: 0,
		},
		{
			name:   "community meets default policy",
			policy: DefaultPolicy(),
			result: VerifyResult{
				Level:       TrustCommunity,
				DigestMatch: true,
			},
			wantViolations: 0,
		},
		{
			name:   "unverified fails default policy",
			policy: DefaultPolicy(),
			result: VerifyResult{
				Level:       TrustUnverified,
				DigestMatch: true,
			},
			wantViolations: 1, // trust level below minimum
		},
		{
			name:   "digest mismatch with require digest",
			policy: DefaultPolicy(),
			result: VerifyResult{
				Level:       TrustVerified,
				DigestMatch: false,
			},
			wantViolations: 1, // digest required but failed
		},
		{
			name:   "digest mismatch without require digest",
			policy: PermissivePolicy(),
			result: VerifyResult{
				Level:       TrustUnverified,
				DigestMatch: false,
			},
			wantViolations: 0,
		},
		{
			name:   "community fails enterprise policy",
			policy: EnterprisePolicy(),
			result: VerifyResult{
				Level:       TrustCommunity,
				DigestMatch: true,
			},
			wantViolations: 1, // trust level below verified
		},
		{
			name:   "multiple violations collected",
			policy: EnterprisePolicy(),
			result: VerifyResult{
				Level:       TrustUnverified,
				DigestMatch: false,
			},
			wantViolations: 2, // digest + trust level
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := tt.policy.Enforce(&tt.result)
			if len(violations) != tt.wantViolations {
				t.Errorf("Enforce() returned %d violations, want %d: %v",
					len(violations), tt.wantViolations, violations)
			}
		})
	}
}
