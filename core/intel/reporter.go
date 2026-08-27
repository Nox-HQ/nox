package intel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// reporterLabel is the fixed message the salt authenticates. Deriving the id
// through an HMAC rather than hashing the salt directly means the salt itself
// is never recoverable from anything transmitted, even if the derivation is
// known.
const reporterLabel = "nox-intelligence-reporter-v1"

// DefaultSaltPath returns where the private reporter salt is kept.
func DefaultSaltPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".nox", "reporter-salt")
	}
	return filepath.Join(home, ".nox", "reporter-salt")
}

// ReporterID returns this installation's opaque, stable identifier, creating
// the private salt on first use.
//
// The service counts distinct reporters without learning who they are, so the
// identifier must be stable across scans and non-reversible. It is an HMAC over
// a fixed label keyed by 32 random bytes that never leave the machine: two
// scans from this installation produce the same id, two installations produce
// different ids, and the id reveals nothing about either.
//
// Stability matters as much as opacity. An id that changed per scan would make
// one noisy installation look like a thousand corroborating ones, which is
// precisely the confusion the independence rule exists to prevent.
func ReporterID(saltPath string) (string, error) {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	salt, err := loadOrCreateSalt(saltPath)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(reporterLabel))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func loadOrCreateSalt(path string) ([]byte, error) {
	switch salt, err := os.ReadFile(path); {
	case err == nil && len(salt) >= 32:
		return salt, nil
	case err != nil && !os.IsNotExist(err):
		return nil, fmt.Errorf("reading reporter salt: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating reporter salt: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating salt directory: %w", err)
	}
	// 0600, and written whole. The salt is the only thing linking this
	// installation to its reported observations; a world-readable one would
	// let anything else on the machine impersonate this reporter.
	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return nil, fmt.Errorf("writing reporter salt: %w", err)
	}
	return salt, nil
}
