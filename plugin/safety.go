// Package plugin implements the plugin host runtime for Hardline.
// It manages plugin lifecycle (discover, connect, handshake, invoke, shutdown),
// validates safety constraints, converts between proto and domain types,
// and merges plugin results into ScanResult.
package plugin

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
)

// RiskClass classifies the level of system interaction a plugin requires.
type RiskClass string

const (
	// RiskClassPassive indicates read-only analysis with no side effects.
	RiskClassPassive RiskClass = "passive"
	// RiskClassActive indicates the plugin may modify files or state.
	RiskClassActive RiskClass = "active"
	// RiskClassRuntime indicates the plugin may execute arbitrary code.
	RiskClassRuntime RiskClass = "runtime"
)

// Policy defines the safety bounds a plugin must operate within.
// The host validates each plugin's manifest against this policy
// before allowing registration.
type Policy struct {
	AllowedNetworkHosts    []string
	AllowedNetworkCIDRs    []string
	AllowedFilePaths       []string
	AllowedEnvVars         []string
	MaxRiskClass           RiskClass
	AllowConfirmationReqd  bool
	MaxArtifactBytes       int64
	MaxConcurrency         int
	ToolInvocationTimeout  time.Duration
}

// DefaultPolicy returns a conservative policy suitable for untrusted plugins:
// no network access, passive-only, 10MB artifact limit, 30s timeout.
func DefaultPolicy() Policy {
	return Policy{
		MaxRiskClass:          RiskClassPassive,
		MaxArtifactBytes:      10 * 1024 * 1024, // 10 MB
		ToolInvocationTimeout: 30 * time.Second,
	}
}

// PolicyViolation describes a single safety constraint that a plugin
// manifest violates.
type PolicyViolation struct {
	Field   string
	Message string
}

// Error implements the error interface for PolicyViolation.
func (v PolicyViolation) Error() string {
	return fmt.Sprintf("policy violation on %s: %s", v.Field, v.Message)
}

// ValidateManifest checks a plugin's manifest against the given policy.
// It returns all violations found, not just the first.
// A nil safety requirement in the manifest means no requirements, which always passes.
func ValidateManifest(manifest *pluginv1.GetManifestResponse, policy Policy) []PolicyViolation {
	if manifest == nil {
		return nil
	}
	safety := manifest.GetSafety()
	if safety == nil {
		return nil
	}

	var violations []PolicyViolation

	// Check network hosts.
	for _, host := range safety.GetNetworkHosts() {
		if !hostAllowed(host, policy.AllowedNetworkHosts) {
			violations = append(violations, PolicyViolation{
				Field:   "network_hosts",
				Message: fmt.Sprintf("host %q not allowed by policy", host),
			})
		}
	}

	// Check network CIDRs.
	for _, cidr := range safety.GetNetworkCidrs() {
		if !stringInSlice(cidr, policy.AllowedNetworkCIDRs) {
			violations = append(violations, PolicyViolation{
				Field:   "network_cidrs",
				Message: fmt.Sprintf("CIDR %q not allowed by policy", cidr),
			})
		}
	}

	// Check file paths.
	for _, fp := range safety.GetFilePaths() {
		if !pathAllowed(fp, policy.AllowedFilePaths) {
			violations = append(violations, PolicyViolation{
				Field:   "file_paths",
				Message: fmt.Sprintf("path %q not allowed by policy", fp),
			})
		}
	}

	// Check env vars.
	for _, ev := range safety.GetEnvVars() {
		if !stringInSlice(ev, policy.AllowedEnvVars) {
			violations = append(violations, PolicyViolation{
				Field:   "env_vars",
				Message: fmt.Sprintf("env var %q not allowed by policy", ev),
			})
		}
	}

	// Check risk class.
	if rc := safety.GetRiskClass(); rc != "" {
		if riskClassLevel(RiskClass(rc)) > riskClassLevel(policy.MaxRiskClass) {
			violations = append(violations, PolicyViolation{
				Field:   "risk_class",
				Message: fmt.Sprintf("plugin requires %q but policy allows at most %q", rc, policy.MaxRiskClass),
			})
		}
	}

	// Check confirmation requirement.
	if safety.GetNeedsConfirmation() && !policy.AllowConfirmationReqd {
		violations = append(violations, PolicyViolation{
			Field:   "needs_confirmation",
			Message: "plugin requires user confirmation but policy does not allow it",
		})
	}

	// Check artifact byte limit.
	maxAllowed := policy.MaxArtifactBytes
	if maxAllowed == 0 {
		maxAllowed = 10 * 1024 * 1024 // default 10 MB
	}
	if requested := safety.GetMaxArtifactBytes(); requested > maxAllowed {
		violations = append(violations, PolicyViolation{
			Field:   "max_artifact_bytes",
			Message: fmt.Sprintf("plugin requests %d bytes but policy allows at most %d", requested, maxAllowed),
		})
	}

	return violations
}

// riskClassLevel maps a RiskClass to an ordinal for comparison.
func riskClassLevel(rc RiskClass) int {
	switch rc {
	case RiskClassPassive:
		return 0
	case RiskClassActive:
		return 1
	case RiskClassRuntime:
		return 2
	default:
		return -1
	}
}

// hostAllowed checks if a requested host matches any allowed pattern.
// Patterns support wildcard prefix matching: "*.example.com" matches
// "api.example.com" and "sub.api.example.com".
func hostAllowed(requested string, allowed []string) bool {
	for _, pattern := range allowed {
		if hostMatchesPattern(requested, pattern) {
			return true
		}
	}
	return false
}

// hostMatchesPattern checks a single host against a pattern.
// Exact match or wildcard prefix match (e.g., "*.example.com").
func hostMatchesPattern(requested, pattern string) bool {
	if requested == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g., ".example.com"
		return strings.HasSuffix(requested, suffix)
	}
	return false
}

// pathAllowed checks if a requested path is contained within any allowed path.
// Uses filepath.Rel for containment checking, consistent with server/server.go.
func pathAllowed(requested string, allowed []string) bool {
	for _, allowedPath := range allowed {
		rel, err := filepath.Rel(allowedPath, requested)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

// stringInSlice checks if a string is present in the slice.
func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
