package trust

import "testing"

func TestDefaultTrustPolicy(t *testing.T) {
	p := DefaultTrustPolicy()
	if p.MinTrustLevel != TrustCommunity {
		t.Errorf("MinTrustLevel = %v, want %v", p.MinTrustLevel, TrustCommunity)
	}
	if !p.RequireDigest {
		t.Error("RequireDigest should be true")
	}
	if len(p.AllowedAPIVersions) != 1 || p.AllowedAPIVersions[0] != "v1" {
		t.Errorf("AllowedAPIVersions = %v, want [v1]", p.AllowedAPIVersions)
	}
}

func TestEnterpriseTrustPolicy(t *testing.T) {
	p := EnterpriseTrustPolicy()
	if p.MinTrustLevel != TrustVerified {
		t.Errorf("MinTrustLevel = %v, want %v", p.MinTrustLevel, TrustVerified)
	}
	if !p.RequireDigest {
		t.Error("RequireDigest should be true")
	}
}

func TestPermissiveTrustPolicy(t *testing.T) {
	p := PermissiveTrustPolicy()
	if p.MinTrustLevel != TrustUnverified {
		t.Errorf("MinTrustLevel = %v, want %v", p.MinTrustLevel, TrustUnverified)
	}
	if p.RequireDigest {
		t.Error("RequireDigest should be false")
	}
}

func TestCheckAPIVersion(t *testing.T) {
	tests := []struct {
		name           string
		policy         TrustPolicy
		apiVersion     string
		wantViolations int
	}{
		{
			name:           "allowed version",
			policy:         DefaultTrustPolicy(),
			apiVersion:     "v1",
			wantViolations: 0,
		},
		{
			name:           "disallowed version",
			policy:         DefaultTrustPolicy(),
			apiVersion:     "v2",
			wantViolations: 1,
		},
		{
			name:           "empty version",
			policy:         DefaultTrustPolicy(),
			apiVersion:     "",
			wantViolations: 1,
		},
		{
			name: "multiple allowed versions",
			policy: TrustPolicy{
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
		policy         TrustPolicy
		result         VerifyResult
		wantViolations int
	}{
		{
			name:   "verified meets default policy",
			policy: DefaultTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustVerified,
				DigestMatch: true,
			},
			wantViolations: 0,
		},
		{
			name:   "community meets default policy",
			policy: DefaultTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustCommunity,
				DigestMatch: true,
			},
			wantViolations: 0,
		},
		{
			name:   "unverified fails default policy",
			policy: DefaultTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustUnverified,
				DigestMatch: true,
			},
			wantViolations: 1, // trust level below minimum
		},
		{
			name:   "digest mismatch with require digest",
			policy: DefaultTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustVerified,
				DigestMatch: false,
			},
			wantViolations: 1, // digest required but failed
		},
		{
			name:   "digest mismatch without require digest",
			policy: PermissiveTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustUnverified,
				DigestMatch: false,
			},
			wantViolations: 0,
		},
		{
			name:   "community fails enterprise policy",
			policy: EnterpriseTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustCommunity,
				DigestMatch: true,
			},
			wantViolations: 1, // trust level below verified
		},
		{
			name:   "multiple violations collected",
			policy: EnterpriseTrustPolicy(),
			result: VerifyResult{
				TrustLevel:  TrustUnverified,
				DigestMatch: false,
			},
			wantViolations: 2, // digest + trust level
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := tt.policy.Enforce(tt.result)
			if len(violations) != tt.wantViolations {
				t.Errorf("Enforce() returned %d violations, want %d: %v",
					len(violations), tt.wantViolations, violations)
			}
		})
	}
}
