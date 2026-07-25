package feed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Sign computes the feed's content digest and attaches an Ed25519 signature over
// the canonical entry bytes — the same bytes the digest covers. It is the
// signing side of the format's verification seam (see Ed25519Verifier), used by
// the out-of-band publish pipeline (cmd/slopfeed): a maintainer holds the
// private half; nox verifies against the published public half.
//
// The signer's public key is recorded in Signature.PublicKeyPEM for
// transparency and offline diagnosis only. A verifier NEVER trusts that
// self-described key — Ed25519Verifier checks against a key the operator pinned
// out of band, so embedding the public key cannot be used to forge trust.
//
// keyID is a free-form label identifying which signing key was used (rotation,
// audit). Sign always (re)computes the digest first, so an entry mutation after
// SetDigest cannot slip past unsigned.
func (f *Feed) Sign(priv ed25519.PrivateKey, keyID string) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ed25519 private key has wrong size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	f.SetDigest()
	content := CanonicalEntries(f.Entries)
	sig := ed25519.Sign(priv, content)

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("deriving public key from private key")
	}
	f.Signature = &Signature{
		Algorithm:    "ed25519",
		KeyID:        keyID,
		PublicKeyPEM: EncodePublicKeyPEM(pub),
		Value:        base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// EncodePublicKeyPEM encodes a raw Ed25519 public key as a PEM block of type
// "ED25519 PUBLIC KEY" (raw 32-byte body). This is the exact form
// PEMEd25519Verifier accepts, so a key emitted here round-trips into a verifier
// without crypto/x509. The publish pipeline writes this alongside the feed so
// operators can pin it via scan.slop.signature_key_path.
func EncodePublicKeyPEM(pub ed25519.PublicKey) string {
	block := &pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub}
	return string(pem.EncodeToMemory(block))
}
