// Package mcpfeed consumes NOX Intelligence's signed MCP / AI-component
// advisory feed (GET /v1/feeds/mcp, contract in nox-intelligence
// docs/mcp-feed.md).
//
// What an entry claims, exactly: a PUBLIC advisory affects this package in
// these ranges, and the package (by name) or the advisory (by its own text)
// concerns the Model Context Protocol. It does not say the package is unsafe,
// that an application using it is exploitable, or that a package that is not
// listed is safe. This package reports entries as "an advisory affects this MCP
// server package" and nothing stronger.
//
// Trust model: the same as the slopsquat feed's. A digest over canonical
// entries, an Ed25519 signature checked against a key the operator pinned out
// of band (never the key the feed describes itself with), and fail-closed
// everywhere: a feed that does not verify is never returned. The signature is
// domain-separated by a fixed prefix, so a signature made for the slopsquat
// feed under the same key cannot verify as this one.
package mcpfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/nox-hq/nox-core/slopfeed"
)

// Schema is the feed schema identifier this package understands.
const Schema = "mcp-advisories/v1"

// SignedContext prefixes the signed bytes. It must equal the service's
// MCPFeedContext byte for byte.
const SignedContext = "nox-intelligence/mcp-advisories/v1\n"

// Entry kinds.
const (
	KindVulnerability      = "vulnerability"
	KindMaliciousPackage   = "malicious_package"
	KindPublishedCandidate = "published_candidate"
)

// Bases a classification can rest on. BasisAdvisoryText is the weakest: the
// package's name says nothing about MCP and only the advisory's own prose does.
const (
	BasisPackageName  = "package_name"
	BasisAdvisoryText = "advisory_text"
)

// Range is one affected interval of a package, in the advisory's own terms.
type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Entry is one advisory for one MCP-classified package. Field order is part of
// the canonical encoding and must not change.
type Entry struct {
	Ecosystem  string   `json:"ecosystem"`
	Package    string   `json:"package"`
	AdvisoryID string   `json:"advisory_id"`
	Aliases    []string `json:"aliases"`
	Kind       string   `json:"kind"`
	Component  string   `json:"component"`
	Basis      string   `json:"basis"`
	Rule       string   `json:"rule"`
	Summary    string   `json:"summary"`
	Ranges     []Range  `json:"ranges"`
	// VersionRange is a candidate's reporter-supplied range expression; empty
	// for OSV records, whose ranges are in Ranges.
	VersionRange string `json:"version_range,omitempty"`
	Modified     string `json:"modified,omitempty"`
}

// Signature mirrors the service's signature block.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
	Value     string `json:"value"`
}

// Feed is the artifact. Only Entries are covered by the digest and signature.
type Feed struct {
	SchemaVersion string     `json:"schema_version"`
	Version       string     `json:"version"`
	GeneratedAt   string     `json:"generated_at"`
	Source        string     `json:"source"`
	Claim         string     `json:"claim"`
	Digest        string     `json:"digest"`
	Signature     *Signature `json:"signature,omitempty"`
	Entries       []Entry    `json:"entries"`
}

// Canonical is the deterministic serialisation the digest and the signature
// cover: sorted by (ecosystem, package, advisory id, kind), slices non-nil and
// sorted, fields in struct order. It reproduces the service's
// CanonicalMCPEntries; the cross-implementation test pins that.
func Canonical(entries []Entry) ([]byte, error) {
	sorted := make([]Entry, len(entries))
	for i, e := range entries {
		e.Aliases = append([]string{}, e.Aliases...)
		sort.Strings(e.Aliases)
		e.Ranges = append([]Range{}, e.Ranges...)
		sort.Slice(e.Ranges, func(a, b int) bool {
			x, y := e.Ranges[a], e.Ranges[b]
			if x.Introduced != y.Introduced {
				return x.Introduced < y.Introduced
			}
			if x.Fixed != y.Fixed {
				return x.Fixed < y.Fixed
			}
			return x.LastAffected < y.LastAffected
		})
		sorted[i] = e
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		return a.Kind < b.Kind
	})
	return json.Marshal(sorted)
}

// Digest is "sha256:" and the hex SHA-256 of the canonical entries.
func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Errors Parse distinguishes, so a caller can say which check failed.
var (
	ErrSchema    = errors.New("unsupported mcp feed schema")
	ErrDigest    = errors.New("mcp feed digest mismatch")
	ErrSignature = errors.New("mcp feed signature does not verify")
	ErrUnsigned  = errors.New("mcp feed carries no ed25519 signature")
)

// Parse decodes a feed, recomputes its digest and verifies its signature under
// verify (a pinned key; see slopfeed.PEMEd25519Verifier). It fails closed: a
// feed that does not verify is never returned, and a nil verifier is an error
// rather than a skipped check, because an unverified advisory feed is a
// blocklist anyone on the path can edit.
func Parse(body []byte, verify slopfeed.SignatureVerifier) (*Feed, error) {
	if verify == nil {
		return nil, errors.New("mcp feed: no pinned public key, so the feed cannot be verified")
	}
	var f Feed
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parsing mcp feed: %w", err)
	}
	if f.SchemaVersion != Schema {
		return nil, fmt.Errorf("%w %q", ErrSchema, f.SchemaVersion)
	}
	content, err := Canonical(f.Entries)
	if err != nil {
		return nil, err
	}
	if got := Digest(content); got != f.Digest {
		return nil, fmt.Errorf("%w: computed %s, feed says %s", ErrDigest, got, f.Digest)
	}
	if f.Signature == nil || f.Signature.Algorithm != slopfeed.AlgorithmEd25519 {
		return nil, ErrUnsigned
	}
	sig := &slopfeed.Signature{Algorithm: f.Signature.Algorithm, KeyID: f.Signature.KeyID, Value: f.Signature.Value}
	if err := verify(append([]byte(SignedContext), content...), sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return &f, nil
}
