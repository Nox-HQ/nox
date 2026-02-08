package plugin

import (
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()

	if p.MaxRiskClass != RiskClassPassive {
		t.Errorf("MaxRiskClass = %q, want %q", p.MaxRiskClass, RiskClassPassive)
	}
	if p.MaxArtifactBytes != 10*1024*1024 {
		t.Errorf("MaxArtifactBytes = %d, want %d", p.MaxArtifactBytes, 10*1024*1024)
	}
	if len(p.AllowedNetworkHosts) != 0 {
		t.Errorf("AllowedNetworkHosts should be empty, got %v", p.AllowedNetworkHosts)
	}
	if len(p.AllowedFilePaths) != 0 {
		t.Errorf("AllowedFilePaths should be empty, got %v", p.AllowedFilePaths)
	}
	if p.ToolInvocationTimeout.Seconds() != 30 {
		t.Errorf("ToolInvocationTimeout = %v, want 30s", p.ToolInvocationTimeout)
	}
	if p.RequestsPerMinute != 0 {
		t.Errorf("RequestsPerMinute = %d, want 0 (unlimited)", p.RequestsPerMinute)
	}
	if p.BandwidthBytesPerMin != 0 {
		t.Errorf("BandwidthBytesPerMin = %d, want 0 (unlimited)", p.BandwidthBytesPerMin)
	}
}

func TestValidateManifest_NilSafety(t *testing.T) {
	manifest := &pluginv1.GetManifestResponse{
		Name:       "test-plugin",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Safety:     nil,
	}

	violations := ValidateManifest(manifest, DefaultPolicy())
	if len(violations) != 0 {
		t.Errorf("nil safety should pass, got %d violations: %v", len(violations), violations)
	}
}

func TestValidateManifest_NilManifest(t *testing.T) {
	violations := ValidateManifest(nil, DefaultPolicy())
	if len(violations) != 0 {
		t.Errorf("nil manifest should pass, got %d violations", len(violations))
	}
}

func TestValidateManifest_EmptySafety(t *testing.T) {
	manifest := &pluginv1.GetManifestResponse{
		Safety: &pluginv1.SafetyRequirements{},
	}
	violations := ValidateManifest(manifest, DefaultPolicy())
	if len(violations) != 0 {
		t.Errorf("empty safety should pass, got %d violations: %v", len(violations), violations)
	}
}

func TestValidateManifest_NetworkHosts(t *testing.T) {
	tests := []struct {
		name       string
		requested  []string
		allowed    []string
		wantViolN  int
	}{
		{
			name:      "exact match allowed",
			requested: []string{"api.example.com"},
			allowed:   []string{"api.example.com"},
			wantViolN: 0,
		},
		{
			name:      "wildcard match allowed",
			requested: []string{"api.example.com"},
			allowed:   []string{"*.example.com"},
			wantViolN: 0,
		},
		{
			name:      "subdomain wildcard match",
			requested: []string{"deep.sub.example.com"},
			allowed:   []string{"*.example.com"},
			wantViolN: 0,
		},
		{
			name:      "no match denied",
			requested: []string{"evil.com"},
			allowed:   []string{"*.example.com"},
			wantViolN: 1,
		},
		{
			name:      "empty allowed denies all",
			requested: []string{"api.example.com"},
			allowed:   nil,
			wantViolN: 1,
		},
		{
			name:      "multiple hosts partial match",
			requested: []string{"api.example.com", "evil.com"},
			allowed:   []string{"*.example.com"},
			wantViolN: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					NetworkHosts: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.AllowedNetworkHosts = tt.allowed

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_NetworkCIDRs(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		allowed   []string
		wantViolN int
	}{
		{
			name:      "exact CIDR match",
			requested: []string{"10.0.0.0/8"},
			allowed:   []string{"10.0.0.0/8"},
			wantViolN: 0,
		},
		{
			name:      "CIDR not in allowed list",
			requested: []string{"192.168.0.0/16"},
			allowed:   []string{"10.0.0.0/8"},
			wantViolN: 1,
		},
		{
			name:      "empty allowed denies all",
			requested: []string{"10.0.0.0/8"},
			allowed:   nil,
			wantViolN: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					NetworkCidrs: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.AllowedNetworkCIDRs = tt.allowed

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_FilePaths(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		allowed   []string
		wantViolN int
	}{
		{
			name:      "path within allowed directory",
			requested: []string{"/workspace/project/src/main.go"},
			allowed:   []string{"/workspace/project"},
			wantViolN: 0,
		},
		{
			name:      "exact path match",
			requested: []string{"/workspace/project"},
			allowed:   []string{"/workspace/project"},
			wantViolN: 0,
		},
		{
			name:      "path outside allowed directory",
			requested: []string{"/etc/passwd"},
			allowed:   []string{"/workspace/project"},
			wantViolN: 1,
		},
		{
			name:      "path traversal attempt",
			requested: []string{"/workspace/project/../../etc/passwd"},
			allowed:   []string{"/workspace/project"},
			wantViolN: 1,
		},
		{
			name:      "empty allowed denies all",
			requested: []string{"/workspace/project/file"},
			allowed:   nil,
			wantViolN: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					FilePaths: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.AllowedFilePaths = tt.allowed

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_EnvVars(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		allowed   []string
		wantViolN int
	}{
		{
			name:      "allowed env var",
			requested: []string{"HOME"},
			allowed:   []string{"HOME", "PATH"},
			wantViolN: 0,
		},
		{
			name:      "denied env var",
			requested: []string{"SECRET_KEY"},
			allowed:   []string{"HOME"},
			wantViolN: 1,
		},
		{
			name:      "empty allowed denies all",
			requested: []string{"HOME"},
			allowed:   nil,
			wantViolN: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					EnvVars: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.AllowedEnvVars = tt.allowed

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_RiskClass(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		maxPolicy RiskClass
		wantViolN int
	}{
		{
			name:      "passive within passive",
			requested: "passive",
			maxPolicy: RiskClassPassive,
			wantViolN: 0,
		},
		{
			name:      "passive within active",
			requested: "passive",
			maxPolicy: RiskClassActive,
			wantViolN: 0,
		},
		{
			name:      "active within active",
			requested: "active",
			maxPolicy: RiskClassActive,
			wantViolN: 0,
		},
		{
			name:      "active exceeds passive",
			requested: "active",
			maxPolicy: RiskClassPassive,
			wantViolN: 1,
		},
		{
			name:      "runtime exceeds active",
			requested: "runtime",
			maxPolicy: RiskClassActive,
			wantViolN: 1,
		},
		{
			name:      "runtime within runtime",
			requested: "runtime",
			maxPolicy: RiskClassRuntime,
			wantViolN: 0,
		},
		{
			name:      "empty risk class passes",
			requested: "",
			maxPolicy: RiskClassPassive,
			wantViolN: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					RiskClass: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.MaxRiskClass = tt.maxPolicy

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_ArtifactBytes(t *testing.T) {
	tests := []struct {
		name      string
		requested int64
		maxPolicy int64
		wantViolN int
	}{
		{
			name:      "within limit",
			requested: 5 * 1024 * 1024,
			maxPolicy: 10 * 1024 * 1024,
			wantViolN: 0,
		},
		{
			name:      "at limit",
			requested: 10 * 1024 * 1024,
			maxPolicy: 10 * 1024 * 1024,
			wantViolN: 0,
		},
		{
			name:      "exceeds limit",
			requested: 20 * 1024 * 1024,
			maxPolicy: 10 * 1024 * 1024,
			wantViolN: 1,
		},
		{
			name:      "zero requested passes",
			requested: 0,
			maxPolicy: 10 * 1024 * 1024,
			wantViolN: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					MaxArtifactBytes: tt.requested,
				},
			}
			policy := DefaultPolicy()
			policy.MaxArtifactBytes = tt.maxPolicy

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_NeedsConfirmation(t *testing.T) {
	tests := []struct {
		name        string
		needs       bool
		policyAllow bool
		wantViolN   int
	}{
		{
			name:        "not needed",
			needs:       false,
			policyAllow: false,
			wantViolN:   0,
		},
		{
			name:        "needed and allowed",
			needs:       true,
			policyAllow: true,
			wantViolN:   0,
		},
		{
			name:        "needed but not allowed",
			needs:       true,
			policyAllow: false,
			wantViolN:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &pluginv1.GetManifestResponse{
				Safety: &pluginv1.SafetyRequirements{
					NeedsConfirmation: tt.needs,
				},
			}
			policy := DefaultPolicy()
			policy.AllowConfirmationReqd = tt.policyAllow

			violations := ValidateManifest(manifest, policy)
			if len(violations) != tt.wantViolN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolN, violations)
			}
		})
	}
}

func TestValidateManifest_MultipleViolations(t *testing.T) {
	manifest := &pluginv1.GetManifestResponse{
		Safety: &pluginv1.SafetyRequirements{
			NetworkHosts:      []string{"evil.com"},
			RiskClass:         "runtime",
			MaxArtifactBytes:  100 * 1024 * 1024,
			NeedsConfirmation: true,
			EnvVars:           []string{"SECRET_KEY"},
		},
	}
	violations := ValidateManifest(manifest, DefaultPolicy())

	// Expect: network host, risk class, artifact bytes, confirmation, env var = 5 violations.
	if len(violations) != 5 {
		t.Errorf("got %d violations, want 5: %v", len(violations), violations)
	}
}

func TestRiskClassLevel(t *testing.T) {
	if riskClassLevel(RiskClassPassive) >= riskClassLevel(RiskClassActive) {
		t.Error("passive should be less than active")
	}
	if riskClassLevel(RiskClassActive) >= riskClassLevel(RiskClassRuntime) {
		t.Error("active should be less than runtime")
	}
	if riskClassLevel(RiskClass("unknown")) != -1 {
		t.Error("unknown risk class should return -1")
	}
}

func TestHostMatchesPattern(t *testing.T) {
	tests := []struct {
		requested string
		pattern   string
		want      bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"deep.sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"evil.com", "*.example.com", false},
		{"api.example.com", "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.requested+"_vs_"+tt.pattern, func(t *testing.T) {
			got := hostMatchesPattern(tt.requested, tt.pattern)
			if got != tt.want {
				t.Errorf("hostMatchesPattern(%q, %q) = %v, want %v", tt.requested, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestPolicyViolation_Error(t *testing.T) {
	v := PolicyViolation{Field: "network_hosts", Message: "host not allowed"}
	got := v.Error()
	want := "policy violation on network_hosts: host not allowed"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
