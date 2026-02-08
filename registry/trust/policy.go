package trust

import "fmt"

// TrustPolicy defines the minimum trust requirements for artifact verification.
type TrustPolicy struct {
	MinTrustLevel      TrustLevel
	AllowedAPIVersions []string
	RequireDigest      bool
}

// DefaultTrustPolicy returns a policy requiring community-level trust,
// API version "v1", and digest verification.
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{
		MinTrustLevel:      TrustCommunity,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      true,
	}
}

// EnterpriseTrustPolicy returns a strict policy requiring verified-level trust,
// API version "v1", and digest verification.
func EnterpriseTrustPolicy() TrustPolicy {
	return TrustPolicy{
		MinTrustLevel:      TrustVerified,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      true,
	}
}

// PermissiveTrustPolicy returns a relaxed policy accepting unverified artifacts
// with API version "v1" and no digest requirement.
func PermissiveTrustPolicy() TrustPolicy {
	return TrustPolicy{
		MinTrustLevel:      TrustUnverified,
		AllowedAPIVersions: []string{"v1"},
		RequireDigest:      false,
	}
}

// CheckAPIVersion validates that the given API version is allowed by the policy.
// Returns violations if the version is not in the allowed list.
func (p TrustPolicy) CheckAPIVersion(apiVersion string) []TrustViolation {
	if apiVersion == "" {
		return []TrustViolation{{
			Field:   "api_version",
			Message: "API version is empty",
		}}
	}

	for _, allowed := range p.AllowedAPIVersions {
		if apiVersion == allowed {
			return nil
		}
	}

	return []TrustViolation{{
		Field:   "api_version",
		Message: fmt.Sprintf("API version %q not in allowed versions %v", apiVersion, p.AllowedAPIVersions),
	}}
}

// Enforce checks a verification result against the policy.
// It returns all violations found, not just the first.
func (p TrustPolicy) Enforce(result VerifyResult) []TrustViolation {
	var violations []TrustViolation

	if p.RequireDigest && !result.DigestMatch {
		violations = append(violations, TrustViolation{
			Field:   "digest",
			Message: "digest verification failed but policy requires it",
		})
	}

	if result.TrustLevel < p.MinTrustLevel {
		violations = append(violations, TrustViolation{
			Field:   "trust_level",
			Message: fmt.Sprintf("trust level %q is below minimum %q", result.TrustLevel, p.MinTrustLevel),
		})
	}

	return violations
}
