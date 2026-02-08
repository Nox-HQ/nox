package trust

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
)

// ed25519PKIXPrefix is the ASN.1 DER prefix for Ed25519 public keys encoded
// with the PKIX SubjectPublicKeyInfo structure (OID 1.3.101.112).
// This avoids importing crypto/x509 for a single well-known prefix.
var ed25519PKIXPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00,
}

// VerifySignature verifies an Ed25519 signature over content using the given
// PEM-encoded public key. Returns true if the signature is valid.
func VerifySignature(content, signature, publicKeyPEM []byte) (bool, error) {
	pub, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("parsing public key: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature length: got %d, want %d", len(signature), ed25519.SignatureSize)
	}

	return ed25519.Verify(pub, content, signature), nil
}

// ParsePublicKey parses a PEM-encoded Ed25519 public key. It supports both
// raw 32-byte keys (PEM type "ED25519 PUBLIC KEY") and standard PKIX/DER
// encoded keys (PEM type "PUBLIC KEY").
func ParsePublicKey(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	switch block.Type {
	case "ED25519 PUBLIC KEY":
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("raw Ed25519 key: got %d bytes, want %d", len(block.Bytes), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(block.Bytes), nil

	case "PUBLIC KEY":
		return parsePKIXEd25519(block.Bytes)

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}
}

// parsePKIXEd25519 extracts an Ed25519 public key from a PKIX SubjectPublicKeyInfo
// DER encoding by stripping the known ASN.1 prefix.
func parsePKIXEd25519(der []byte) (ed25519.PublicKey, error) {
	prefixLen := len(ed25519PKIXPrefix)
	expectedLen := prefixLen + ed25519.PublicKeySize

	if len(der) != expectedLen {
		return nil, fmt.Errorf("PKIX Ed25519 key: got %d bytes, want %d", len(der), expectedLen)
	}

	for i := 0; i < prefixLen; i++ {
		if der[i] != ed25519PKIXPrefix[i] {
			return nil, errors.New("PKIX Ed25519 key: invalid ASN.1 prefix")
		}
	}

	return ed25519.PublicKey(der[prefixLen:]), nil
}
