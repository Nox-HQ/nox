package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// fingerprintScheme versions the digest. It is part of the hashed input so that
// changing the recipe cannot silently make old and new fingerprints collide;
// a scheme change is a visible break, not a quiet corruption of clustering.
const fingerprintScheme = "nox-intel-fp-v1"

// Fingerprint is the deterministic identity of a weakness-in-an-artifact.
//
// It hashes exactly five public coordinates: ecosystem, package, normalized
// version, weakness class, and rule id. Nothing else is admissible, and the
// omissions are the point:
//
//   - No file path. A path names the reporter's machine and repository layout.
//     Hashing it would also make the same weakness fingerprint differently for
//     every reporter, which destroys the corroboration the network exists for.
//   - No source content, matched string, or message. A digest of a secret is
//     still a secret: anyone who guesses the value can confirm it against the
//     digest. A fingerprint must be safe to publish even when the observation
//     behind it was not.
//
// Two reporters who see the same weakness in the same artifact therefore
// produce the same fingerprint without either revealing anything about
// themselves — which is precisely the property that makes independent
// corroboration possible.
//
// The version is hashed exactly (after normalization) rather than bucketed into
// a range. Bucketing would merge a vulnerable version with a fixed one and
// manufacture corroboration that does not exist; keeping versions distinct
// leaves candidates precise, and CorrelateAdvisories / Dedupe collapse them
// once a published advisory says which versions actually share a defect.
func Fingerprint(o Observation) string {
	h := sha256.New()
	// NUL separators keep "ab" + "c" distinguishable from "a" + "bc"; without
	// them, adjacent fields could be shifted to forge a collision.
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		fingerprintScheme,
		normalizeEcosystem(o.Ecosystem),
		normalizePackage(o.Package),
		normalizeVersion(o.Version),
		strings.ToLower(strings.TrimSpace(string(o.WeaknessClass))),
		strings.TrimSpace(o.RuleID),
	)
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeEcosystem lowercases and trims an ecosystem name so "NPM" and "npm"
// cluster together.
func normalizeEcosystem(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizePackage canonicalises a package identifier.
//
// Names are lowercased: npm requires lowercase, PyPI normalizes to it, and Go
// module paths are lowercase by convention. The residual risk is merging two
// modules that differ only by case, which is a naming collision upstream would
// already treat as an error — a smaller cost than failing to cluster the same
// package reported with different capitalisation.
func normalizePackage(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, "/")
}

// normalizeVersion canonicalises a version or range expression: no "v" prefix,
// no build metadata (which is not ordered and not part of identity), single
// spaces, lowercase.
func normalizeVersion(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "v")
	return strings.Join(strings.Fields(s), " ")
}

// NewCandidateID derives a stable, human-quotable candidate identifier from a
// fingerprint.
//
// The identifier is a prefix of the fingerprint when the fingerprint is a
// well-formed digest, so an id in a report can be traced back to the cluster it
// names. Anything else is hashed first, so the function is total and a
// malformed input can never produce an id that collides with a real one by
// accident or by construction.
func NewCandidateID(fingerprint string) string {
	fp := strings.TrimSpace(fingerprint)
	if len(fp) == 64 && isHex(fp) {
		return "NOX-CANDIDATE-" + strings.ToUpper(fp[:8])
	}
	sum := sha256.Sum256([]byte("nox-candidate-id-v1\x00" + fp))
	return "NOX-CANDIDATE-" + strings.ToUpper(hex.EncodeToString(sum[:])[:8])
}

// isHex reports whether s is entirely lowercase-or-uppercase hex digits.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}
