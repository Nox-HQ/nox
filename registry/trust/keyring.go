package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Key represents a trusted public key in the keyring.
type Key struct {
	Name         string `json:"name"`
	Fingerprint  string `json:"fingerprint"`    // SHA-256 of raw public key bytes
	PublicKeyPEM string `json:"public_key_pem"`
}

// Keyring holds a set of trusted public keys for signature verification.
type Keyring struct {
	Keys []Key `json:"keys"`
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{}
}

// Add appends a key to the keyring. Duplicate fingerprints are silently skipped.
func (kr *Keyring) Add(k Key) {
	for _, existing := range kr.Keys {
		if existing.Fingerprint == k.Fingerprint {
			return
		}
	}
	kr.Keys = append(kr.Keys, k)
}

// Find returns the key with the given fingerprint, or nil if not found.
func (kr *Keyring) Find(fingerprint string) *Key {
	for i := range kr.Keys {
		if kr.Keys[i].Fingerprint == fingerprint {
			return &kr.Keys[i]
		}
	}
	return nil
}

// Remove deletes the key with the given fingerprint.
// Returns an error if the fingerprint is not found.
func (kr *Keyring) Remove(fingerprint string) error {
	for i, k := range kr.Keys {
		if k.Fingerprint == fingerprint {
			kr.Keys = append(kr.Keys[:i], kr.Keys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("key %q not found in keyring", fingerprint)
}

// NewKey creates a Key from a name and PEM-encoded public key.
// It parses the key to derive the fingerprint.
func NewKey(name string, publicKeyPEM []byte) (Key, error) {
	pub, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return Key{}, fmt.Errorf("parsing public key: %w", err)
	}
	return Key{
		Name:         name,
		Fingerprint:  KeyFingerprint(pub),
		PublicKeyPEM: string(publicKeyPEM),
	}, nil
}

// KeyFingerprint computes the SHA-256 fingerprint of a raw Ed25519 public key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(h[:])
}

// ExportKeyPEM encodes an Ed25519 public key as a raw PEM block.
func ExportKeyPEM(pub ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte(pub),
	})
}

// LoadKeyring reads a keyring from a JSON file. If the file does not exist,
// it returns an empty keyring without error, matching LoadConfig() semantics.
func LoadKeyring(path string) (*Keyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewKeyring(), nil
		}
		return nil, err
	}

	var kr Keyring
	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("corrupt keyring at %q: %w", path, err)
	}
	return &kr, nil
}

// SaveKeyring writes a keyring to a JSON file using atomic write (temp + rename).
// It creates parent directories as needed.
func SaveKeyring(path string, kr *Keyring) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating keyring dir: %w", err)
	}

	data, err := json.MarshalIndent(kr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling keyring: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing temp keyring file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming keyring file: %w", err)
	}

	return nil
}

// DefaultKeyringPath returns the default keyring file location:
// ~/.hardline/trust/keyring.json
func DefaultKeyringPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".hardline", "trust", "keyring.json")
}
