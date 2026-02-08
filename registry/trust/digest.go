package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Digest represents a content-addressable digest with algorithm and hex value.
type Digest struct {
	Algorithm string // "sha256"
	Hex       string // lowercase hex-encoded hash
}

// ParseDigest parses a digest string in "algorithm:hex" format.
// Only "sha256" is supported.
func ParseDigest(s string) (Digest, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return Digest{}, fmt.Errorf("invalid digest format: missing algorithm prefix in %q", s)
	}

	alg, hexVal := parts[0], parts[1]
	if alg != "sha256" {
		return Digest{}, fmt.Errorf("unsupported digest algorithm: %q", alg)
	}

	if len(hexVal) != sha256.Size*2 {
		return Digest{}, fmt.Errorf("invalid sha256 hex length: got %d, want %d", len(hexVal), sha256.Size*2)
	}

	if _, err := hex.DecodeString(hexVal); err != nil {
		return Digest{}, fmt.Errorf("invalid hex in digest: %w", err)
	}

	return Digest{Algorithm: alg, Hex: strings.ToLower(hexVal)}, nil
}

// String returns the digest in "algorithm:hex" format.
func (d Digest) String() string {
	return d.Algorithm + ":" + d.Hex
}

// ComputeDigest computes a SHA-256 digest of data.
func ComputeDigest(data []byte) Digest {
	h := sha256.Sum256(data)
	return Digest{Algorithm: "sha256", Hex: hex.EncodeToString(h[:])}
}

// ComputeDigestReader computes a SHA-256 digest by reading from r.
func ComputeDigestReader(r io.Reader) (Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return Digest{}, fmt.Errorf("computing digest: %w", err)
	}
	return Digest{Algorithm: "sha256", Hex: hex.EncodeToString(h.Sum(nil))}, nil
}

// VerifyDigest computes the SHA-256 digest of data and compares it to the
// expected digest string. Returns true if they match.
func VerifyDigest(data []byte, expected string) (bool, error) {
	exp, err := ParseDigest(expected)
	if err != nil {
		return false, err
	}
	actual := ComputeDigest(data)
	return actual.Hex == exp.Hex, nil
}
