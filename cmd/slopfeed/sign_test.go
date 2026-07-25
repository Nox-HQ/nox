package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

func writePKCS8Key(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key.pem")
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRawKey(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	path := filepath.Join(dir, "raw.pem")
	block := &pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSignFeedProducesVerifiableSignature proves the generator signs with both
// key encodings and that nox's verifier accepts the result under the matching
// public key and rejects it under a different one.
func TestSignFeedProducesVerifiableSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		keyPath string
	}{
		{"pkcs8", writePKCS8Key(t, dir, priv)},
		{"raw", writeRawKey(t, dir, priv)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &feed.Feed{
				SchemaVersion: feed.SchemaVersion,
				Version:       "test",
				Source:        "test",
				Entries: []feed.Entry{{
					Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
					Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
				}},
			}
			pubOut := filepath.Join(dir, tc.name+".pub.pem")
			if _, err := signFeed(f, tc.keyPath, "kid", pubOut); err != nil {
				t.Fatalf("signFeed: %v", err)
			}
			raw := mustMarshal(t, f)

			// Accepts under the correct key.
			if _, err := feed.Parse(raw, feed.VerifyOptions{
				RequireSignature: true, Verifier: feed.Ed25519Verifier(pub),
			}); err != nil {
				t.Fatalf("signed feed must verify: %v", err)
			}
			// Rejects under a different key.
			otherPub, _, _ := ed25519.GenerateKey(nil)
			if _, err := feed.Parse(raw, feed.VerifyOptions{
				RequireSignature: true, Verifier: feed.Ed25519Verifier(otherPub),
			}); err == nil {
				t.Fatalf("signature must not verify under a different key")
			}
			// The written public key file must be usable as a pinned verifier.
			pemBytes, err := os.ReadFile(pubOut)
			if err != nil {
				t.Fatal(err)
			}
			v, err := feed.PEMEd25519Verifier(pemBytes)
			if err != nil {
				t.Fatalf("PEMEd25519Verifier from emitted pubkey: %v", err)
			}
			if _, err := feed.Parse(raw, feed.VerifyOptions{RequireSignature: true, Verifier: v}); err != nil {
				t.Fatalf("emitted public key must verify the feed: %v", err)
			}
		})
	}
}

func TestLoadEd25519PrivateKeyRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEd25519PrivateKey(bad); err == nil {
		t.Fatalf("garbage key must be rejected")
	}
	if _, err := loadEd25519PrivateKey(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatalf("missing key must be rejected")
	}
}

func mustMarshal(t *testing.T, f *feed.Feed) []byte {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
