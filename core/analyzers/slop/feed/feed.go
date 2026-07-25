// Package feed defines the versioned, offline "predictive slopsquat blocklist"
// that nox's SLOP analyzer consumes as an additional deterministic signal.
//
// The feed is a signed, versioned, content-addressed data artifact: a list of
// high-risk package names — per ecosystem — that an LLM is likely to
// hallucinate and that were verified UNREGISTERED (squattable) at generation
// time. Intelligence accumulates centrally (a generator queries registries
// out-of-band), and every device enforces it deterministically and offline —
// the same shape as nox's OSV integration, but with the network fully removed
// from scan time: only the generator touches a registry; the scanner reads a
// frozen artifact.
//
// # Trust model
//
// The format mirrors the plugin registry's trust model (see registry/trust):
//
//   - Every feed carries a content digest, "sha256:<hex>", computed over a
//     canonical serialization of its entries. A consumer recomputes the digest
//     and rejects any feed whose bytes do not match — this catches truncation,
//     tampering, and accidental corruption. Verification fails closed: a feed
//     that does not verify is never trusted, and never crashes the scanner.
//   - The format carries an Ed25519 signature over the same canonical bytes, so
//     a feed is authenticated exactly like a plugin artifact. Signing is done
//     out of band by the publish pipeline (see Sign and cmd/slopfeed); nox
//     verifies against a pinned public key via a pluggable hook
//     (SignatureVerifier) and can be configured to require a valid signature.
//
// A local feed (Load/Bundled) touches no network. A remote feed (LoadRemote)
// fetches over HTTP(S), verifies digest AND signature before use, and caches the
// verified bytes content-addressed on disk so subsequent scans are offline and
// deterministic. Verification always gates use: only bytes that verify are
// cached or returned. The package depends only on the standard library, so it
// does not couple core to the registry package.
package feed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// SchemaVersion is the feed schema identifier this build understands. It is a
// namespaced, versioned string so future breaking changes get a new value and
// an old consumer refuses a feed it cannot interpret rather than misreading it.
const SchemaVersion = "slopsquat-blocklist/v1"

// Ecosystem values used in the feed. These match nox's canonical internal
// ecosystem names (see the slop analyzer), so the consumer can look up an
// imported package without translation.
const (
	EcosystemPyPI = "pypi"
	EcosystemNPM  = "npm"
)

// Tier buckets a squattable name by risk. Only these three tiers are ever
// written to a feed — a name that scores below "medium" is not high-likelihood
// enough to assert as a predictive target.
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
)

// Entry is a single high-risk, currently-unregistered package name.
//
// The only claim an Entry makes is the narrow, defensible one from the
// research: this name was UNREGISTERED (verified at VerifiedAt) and matches a
// high-likelihood hallucination pattern, so an attacker could register it to
// catch hallucinated installs. It never accuses an existing package — the
// generator only ever writes names it re-verified as unregistered.
type Entry struct {
	Name       string  `json:"name"`
	Ecosystem  string  `json:"ecosystem"`             // "pypi" | "npm"
	Pattern    string  `json:"pattern"`               // obvious | composition | typo
	NeighborOf string  `json:"neighbor_of,omitempty"` // real stem it derives from
	Risk       float64 `json:"risk"`                  // [0,1] LLM-emission-derived risk
	Tier       string  `json:"tier"`                  // critical | high | medium
	Reason     string  `json:"reason"`                // human-readable rationale
	VerifiedAt string  `json:"verified_at"`           // date the 404 was confirmed
}

// Signature carries an Ed25519 signature over the feed's canonical entry bytes.
// It is optional: the digest alone provides integrity; the signature adds
// authenticity once a signing pipeline exists. Value is base64-standard.
type Signature struct {
	Algorithm    string `json:"algorithm"` // "ed25519"
	KeyID        string `json:"key_id,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Value        string `json:"value"` // base64(signature)
}

// Feed is the on-disk artifact: metadata plus the entry list, bound together by
// a content digest.
type Feed struct {
	SchemaVersion string     `json:"schema_version"`
	Version       string     `json:"version"`      // human feed version, e.g. "2026.07.25"
	GeneratedAt   string     `json:"generated_at"` // RFC3339 timestamp
	Source        string     `json:"source"`       // generator identity
	Digest        string     `json:"digest"`       // "sha256:<hex>" over CanonicalEntries
	Signature     *Signature `json:"signature,omitempty"`
	Entries       []Entry    `json:"entries"`
}

// CanonicalEntries returns a deterministic byte serialization of entries that
// the digest and any signature are computed over. Entries are sorted by
// (ecosystem, name) so the bytes do not depend on input ordering, and each
// field is emitted in a fixed order via the struct definition. This is the sole
// definition of "the content" for integrity purposes.
func CanonicalEntries(entries []Entry) []byte {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Ecosystem != sorted[j].Ecosystem {
			return sorted[i].Ecosystem < sorted[j].Ecosystem
		}
		return sorted[i].Name < sorted[j].Name
	})
	// json.Marshal of a []Entry is deterministic: struct field order is fixed
	// and there are no maps. Errors are impossible for this concrete type.
	data, _ := json.Marshal(sorted)
	return data
}

// ComputeDigest returns the "sha256:<hex>" digest over the canonical entries.
func ComputeDigest(entries []Entry) string {
	sum := sha256.Sum256(CanonicalEntries(entries))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SetDigest computes and stores the digest for the feed's current entries. The
// generator calls this after assembling entries and before writing the file.
func (f *Feed) SetDigest() { f.Digest = ComputeDigest(f.Entries) }

// verifyDigest recomputes the digest and compares it to the stored value.
func (f *Feed) verifyDigest() error {
	if f.Digest == "" {
		return errors.New("feed carries no digest")
	}
	alg, hexVal, ok := strings.Cut(f.Digest, ":")
	if !ok || alg != "sha256" {
		return fmt.Errorf("unsupported or malformed digest %q", f.Digest)
	}
	if len(hexVal) != sha256.Size*2 {
		return fmt.Errorf("digest hex has wrong length: %d", len(hexVal))
	}
	if _, err := hex.DecodeString(hexVal); err != nil {
		return fmt.Errorf("digest hex invalid: %w", err)
	}
	if got := ComputeDigest(f.Entries); got != f.Digest {
		return fmt.Errorf("feed digest mismatch: computed %s, declared %s", got, f.Digest)
	}
	return nil
}

// SignatureVerifier verifies a feed's signature over its canonical content.
// It returns nil when the signature is valid, an error otherwise. Making it a
// hook lets nox pin a key, defer to cosign, or accept a build-time key without
// this package embedding any trust root.
type SignatureVerifier func(content []byte, sig *Signature) error

// Ed25519Verifier returns a SignatureVerifier that checks the feed's Ed25519
// signature against the given public key, ignoring any key embedded in the feed
// (a self-described key is not a trust root). This mirrors registry/trust's
// Ed25519 signature checking.
func Ed25519Verifier(pub ed25519.PublicKey) SignatureVerifier {
	return func(content []byte, sig *Signature) error {
		if sig == nil {
			return errors.New("no signature present")
		}
		if sig.Algorithm != "ed25519" {
			return fmt.Errorf("unsupported signature algorithm %q", sig.Algorithm)
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Value)
		if err != nil {
			return fmt.Errorf("decoding signature: %w", err)
		}
		if len(raw) != ed25519.SignatureSize {
			return fmt.Errorf("signature has wrong length: %d", len(raw))
		}
		if !ed25519.Verify(pub, content, raw) {
			return errors.New("signature does not verify under the configured key")
		}
		return nil
	}
}

// PEMEd25519Verifier builds an Ed25519Verifier from a PEM-encoded public key.
func PEMEd25519Verifier(pemData []byte) (SignatureVerifier, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block in public key")
	}
	// Accept a raw 32-byte key body; PKIX parsing is left to callers that need
	// it, to keep this package free of crypto/x509.
	if len(block.Bytes) == ed25519.PublicKeySize {
		return Ed25519Verifier(ed25519.PublicKey(block.Bytes)), nil
	}
	return nil, fmt.Errorf("unexpected public key length: %d", len(block.Bytes))
}

// VerifyOptions controls how strictly a feed is verified on load.
type VerifyOptions struct {
	// RequireSignature rejects a feed that has no signature, and requires the
	// signature to verify under Verifier. When false, a signature is verified
	// only if present (and Verifier is set), and its absence is tolerated.
	RequireSignature bool
	// Verifier checks the signature. When nil, signature checking is skipped
	// (digest integrity is always enforced regardless).
	Verifier SignatureVerifier
}

// Loaded is a verified, indexed feed ready for O(1) lookups by the analyzer.
type Loaded struct {
	Feed  *Feed
	index map[string]map[string]Entry // ecosystem -> normalized name -> entry
}

// Parse decodes, verifies, and indexes a feed from raw JSON bytes. It fails
// closed: any decode error, schema mismatch, digest mismatch, or failed
// required-signature check returns a non-nil error and a nil *Loaded, and never
// panics on malformed input.
func Parse(data []byte, opts VerifyOptions) (*Loaded, error) {
	if len(data) == 0 {
		return nil, errors.New("empty feed")
	}
	var f Feed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decoding feed: %w", err)
	}
	if f.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported feed schema %q (want %q)", f.SchemaVersion, SchemaVersion)
	}
	if err := f.verifyDigest(); err != nil {
		return nil, err
	}

	content := CanonicalEntries(f.Entries)
	if opts.RequireSignature {
		if f.Signature == nil {
			return nil, errors.New("feed requires a signature but carries none")
		}
		if opts.Verifier == nil {
			return nil, errors.New("feed requires a signature but no verifier is configured")
		}
		if err := opts.Verifier(content, f.Signature); err != nil {
			return nil, fmt.Errorf("feed signature verification failed: %w", err)
		}
	} else if f.Signature != nil && opts.Verifier != nil {
		// Opportunistic: if a signature is present and we have a verifier, a bad
		// signature is still a hard failure — a present-but-invalid signature is
		// a stronger red flag than no signature at all.
		if err := opts.Verifier(content, f.Signature); err != nil {
			return nil, fmt.Errorf("feed signature verification failed: %w", err)
		}
	}

	idx := make(map[string]map[string]Entry, 2)
	for _, e := range f.Entries {
		eco := e.Ecosystem
		if idx[eco] == nil {
			idx[eco] = make(map[string]Entry)
		}
		idx[eco][NormalizeName(eco, e.Name)] = e
	}
	return &Loaded{Feed: &f, index: idx}, nil
}

// Load reads and verifies a feed from a file path.
func Load(path string, opts VerifyOptions) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading feed %s: %w", path, err)
	}
	return Parse(data, opts)
}

//go:embed data/slopsquat-blocklist.v1.json
var bundledFS embed.FS

// Bundled returns the feed shipped in the repo, verified. It lets the feature
// work out of the box for a project that opts in without hosting its own feed.
func Bundled() (*Loaded, error) {
	data, err := bundledFS.ReadFile("data/slopsquat-blocklist.v1.json")
	if err != nil {
		return nil, fmt.Errorf("reading bundled feed: %w", err)
	}
	return Parse(data, VerifyOptions{})
}

// Lookup reports whether name (in ecosystem) is a high-risk feed entry. Names
// are normalized so that, e.g., "OpenAI_Utils" and "openai-utils" match on
// PyPI. Returns the entry and true on a hit.
func (l *Loaded) Lookup(ecosystem, name string) (Entry, bool) {
	if l == nil {
		return Entry{}, false
	}
	m := l.index[ecosystem]
	if m == nil {
		return Entry{}, false
	}
	e, ok := m[NormalizeName(ecosystem, name)]
	return e, ok
}

// Len returns the number of entries in the feed.
func (l *Loaded) Len() int {
	if l == nil || l.Feed == nil {
		return 0
	}
	return len(l.Feed.Entries)
}

// Version returns the feed's version string.
func (l *Loaded) Version() string {
	if l == nil || l.Feed == nil {
		return ""
	}
	return l.Feed.Version
}

// Digest returns the feed's content digest.
func (l *Loaded) Digest() string {
	if l == nil || l.Feed == nil {
		return ""
	}
	return l.Feed.Digest
}

// NormalizeName canonicalizes a package name for cross-referencing. PyPI names
// follow PEP 503 (lowercase; runs of "._-" collapse to a single "-"); npm names
// are matched case-sensitively (npm lowercases but preserves scopes), trimmed.
func NormalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case EcosystemPyPI:
		name = strings.ToLower(name)
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
		for strings.Contains(name, "--") {
			name = strings.ReplaceAll(name, "--", "-")
		}
		return name
	default:
		return name
	}
}
