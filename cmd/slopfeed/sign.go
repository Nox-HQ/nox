package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

// loadEd25519PrivateKey reads a PEM-encoded Ed25519 private key from path. It
// accepts the two forms a maintainer or CI is likely to hold:
//
//   - PKCS#8 ("PRIVATE KEY"), the default `openssl genpkey -algorithm ed25519`
//     output and what most secret stores round-trip cleanly.
//   - A raw key ("ED25519 PRIVATE KEY") whose body is either the 64-byte full
//     private key or the 32-byte seed.
//
// It fails closed on anything else rather than guessing.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in signing key %s", path)
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 signing key: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not Ed25519 (got %T)", key)
		}
		return priv, nil
	case "ED25519 PRIVATE KEY":
		switch len(block.Bytes) {
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(block.Bytes), nil
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(block.Bytes), nil
		default:
			return nil, fmt.Errorf("raw Ed25519 key has unexpected length %d", len(block.Bytes))
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q for a signing key", block.Type)
	}
}

// signFeed signs f in place with the key at keyPath and, when pubkeyOut is set,
// writes the corresponding public key PEM so the publish pipeline can attach it
// as a downloadable trust anchor. It returns the public key PEM regardless.
func signFeed(f *feed.Feed, keyPath, keyID, pubkeyOut string) (string, error) {
	priv, err := loadEd25519PrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	if err := f.Sign(priv, keyID); err != nil {
		return "", fmt.Errorf("signing feed: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("deriving public key")
	}
	pubPEM := feed.EncodePublicKeyPEM(pub)
	if pubkeyOut != "" {
		if err := os.WriteFile(pubkeyOut, []byte(pubPEM), 0o644); err != nil {
			return "", fmt.Errorf("writing public key %s: %w", pubkeyOut, err)
		}
	}
	return pubPEM, nil
}
