package core

import (
	"testing"

	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
)

// Who answers "is this package vulnerable?" is resolved from four places, and
// the order is the whole contract: an operator who wrote `disabled: true` must
// win over every URL, a URL in .nox.yaml must win over the environment, and
// nothing set at all must mean the service every scan asks — not OSV.dev,
// which the previous default silently was.
func TestIntelligenceEndpoint_Resolution(t *testing.T) {
	cases := []struct {
		name string
		cfg  IntelligenceConfig
		env  string
		want string
	}{
		{"nothing set is the compiled-in service", IntelligenceConfig{}, "", DefaultIntelligenceEndpoint},
		{"environment fills in for an absent config", IntelligenceConfig{}, "https://intel.example.test/", "https://intel.example.test"},
		{"config wins over environment", IntelligenceConfig{Endpoint: "https://a.test"}, "https://b.test", "https://a.test"},
		{"a trailing slash is not part of the endpoint", IntelligenceConfig{Endpoint: " https://a.test/ "}, "", "https://a.test"},
		{"disabled wins over a configured endpoint", IntelligenceConfig{Disabled: true, Endpoint: "https://a.test"}, "", ""},
		{"disabled wins over the environment", IntelligenceConfig{Disabled: true}, "https://b.test", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(IntelligenceEndpointEnv, tc.env)
			if got := tc.cfg.ResolvedEndpoint(); got != tc.want {
				t.Fatalf("ResolvedEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The reference database defaults to public OSV.dev and can be a self-hosted
// mirror; it is the one source that is never the intelligence service, because
// it is what the intelligence service is checked against.
func TestOSVReferenceBaseURL(t *testing.T) {
	if got := (OSVConfig{}).ReferenceBaseURL(); got != osvsource.DefaultBaseURL {
		t.Fatalf("empty base_url = %q, want %q", got, osvsource.DefaultBaseURL)
	}
	if got := (OSVConfig{BaseURL: " https://osv.mirror.test/ "}).ReferenceBaseURL(); got != "https://osv.mirror.test" {
		t.Fatalf("base_url = %q, want the trimmed mirror", got)
	}
}
