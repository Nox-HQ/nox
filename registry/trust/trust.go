// Package trust provides plugin trust and verification primitives for Hardline.
// It validates artifact digests, Ed25519 signatures, and enforces trust policies.
// This package depends only on the Go standard library.
package trust

import (
	"fmt"
	"strings"
	"time"
)

// TrustLevel classifies the level of trust established for an artifact.
// Higher ordinal values indicate stronger trust guarantees.
type TrustLevel int

const (
	// TrustUnverified indicates no valid signature was found.
	TrustUnverified TrustLevel = iota
	// TrustCommunity indicates a valid signature from a key NOT in the keyring.
	TrustCommunity
	// TrustVerified indicates a valid signature from a key IN the keyring.
	TrustVerified
)

// String returns the human-readable name of the trust level.
func (t TrustLevel) String() string {
	switch t {
	case TrustUnverified:
		return "unverified"
	case TrustCommunity:
		return "community"
	case TrustVerified:
		return "verified"
	default:
		return fmt.Sprintf("TrustLevel(%d)", int(t))
	}
}

// ParseTrustLevel parses a trust level string. Returns an error for unknown values.
func ParseTrustLevel(s string) (TrustLevel, error) {
	switch strings.ToLower(s) {
	case "unverified":
		return TrustUnverified, nil
	case "community":
		return TrustCommunity, nil
	case "verified":
		return TrustVerified, nil
	default:
		return 0, fmt.Errorf("unknown trust level: %q", s)
	}
}

// TrustViolation describes a single trust constraint violation.
type TrustViolation struct {
	Field   string
	Message string
}

// Error implements the error interface for TrustViolation.
func (v TrustViolation) Error() string {
	return fmt.Sprintf("trust violation on %s: %s", v.Field, v.Message)
}

// VerifyResult holds the outcome of artifact verification.
type VerifyResult struct {
	TrustLevel     TrustLevel
	DigestMatch    bool
	SignatureValid bool
	SignerKey      string // SHA-256 fingerprint of the signing key
	SignerName     string // name from keyring, empty if unknown
	Violations     []TrustViolation
	VerifiedAt     time.Time
}

// OK returns true if verification passed without any violations and the digest matched.
func (r VerifyResult) OK() bool {
	return len(r.Violations) == 0 && r.DigestMatch
}
