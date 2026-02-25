package trust

import "fmt"

// Policy defines the minimum trust requirements for artifact verification.
type Policy struct {
	MinLevel           Level
	AllowedAPIVersions []string
	RequireDigest      bool
}

// DefaultPolicy returns a policy requiring community-level trust,
// API version "v1", and digest verification.
func DefaultPolicy() Policy {
	return Policy{
		MinLevel:           TrustCommunity,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      true,
	}
}

// EnterprisePolicy returns a strict policy requiring verified-level trust,
// API version "v1", and digest verification.
func EnterprisePolicy() Policy {
	return Policy{
		MinLevel:           TrustVerified,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      true,
	}
}

// PermissivePolicy returns a relaxed policy accepting unverified artifacts
// with API version "v1" and no digest requirement.
func PermissivePolicy() Policy {
	return Policy{
		MinLevel:           TrustUnverified,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      false,
	}
}

// CheckAPIVersion validates that the given API version is allowed by the policy.
// Returns violations if the version is not in the allowed list.
func (p Policy) CheckAPIVersion(apiVersion string) []Violation {
	if apiVersion == "" {
		return []Violation{{
			Field:   "api_version",
			Message: "API version is empty",
		}}
	}

	for _, allowed := range p.AllowedAPIVersions {
		if apiVersion == allowed {
			return nil
		}
	}

	return []Violation{{
		Field:   "api_version",
		Message: fmt.Sprintf("API version %q not in allowed versions %v", apiVersion, p.AllowedAPIVersions),
	}}
}

// Enforce checks a verification result against the policy.
// It returns all violations found, not just the first.
func (p Policy) Enforce(result *VerifyResult) []Violation {
	var violations []Violation

	if p.RequireDigest && !result.DigestMatch {
		violations = append(violations, Violation{
			Field:   "digest",
			Message: "digest verification failed but policy requires it",
		})
	}

	if result.Level < p.MinLevel {
		violations = append(violations, Violation{
			Field:   "trust_level",
			Message: fmt.Sprintf("trust level %q is below minimum %q", result.Level, p.MinLevel),
		})
	}

	return violations
}
