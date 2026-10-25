package intel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// deletionLabel is the fixed message the salt authenticates to give the
// deletion key. A different label from reporterLabel, so the id the service
// sees reveals nothing about the key it must never see.
const deletionLabel = "nox-intelligence-deletion-v1"

// ConsentStatus says whether this installation may contribute.
type ConsentStatus int

const (
	// ConsentNone means the operator never accepted terms on this machine.
	ConsentNone ConsentStatus = iota
	// ConsentStale means the operator accepted an older terms version.
	ConsentStale
	// ConsentGranted means the operator accepted the current terms.
	ConsentGranted
)

// Consent is the recorded acceptance. It is per-installation state beside the
// reporter salt (~/.nox), never project config: .nox.yaml is committed, and a
// cloned repository must not be able to consent on behalf of whoever scans it.
type Consent struct {
	TermsVersion string `json:"terms_version"`
	AcceptedAt   string `json:"accepted_at"`
}

// ConsentPath is where the acceptance lives: next to the salt, so a salt
// override (tests, CI) moves both and they cannot disagree about whose
// installation this is.
func ConsentPath(saltPath string) string {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	return filepath.Join(filepath.Dir(saltPath), "intel-consent.json")
}

// LoadConsent reads the recorded acceptance. A missing or unreadable file is
// no consent; the status says which version, if any, was accepted.
func LoadConsent(saltPath string) (ConsentStatus, Consent) {
	b, err := os.ReadFile(ConsentPath(saltPath))
	if err != nil {
		return ConsentNone, Consent{}
	}
	var c Consent
	if json.Unmarshal(b, &c) != nil || c.TermsVersion == "" {
		return ConsentNone, Consent{}
	}
	if c.TermsVersion != TermsVersion {
		return ConsentStale, c
	}
	return ConsentGranted, c
}

// RecordConsent stores the acceptance of the current terms. at is passed in so
// the package reads no clock.
func RecordConsent(saltPath, at string) error {
	p := ConsentPath(saltPath)
	b, err := json.Marshal(Consent{TermsVersion: TermsVersion, AcceptedAt: at})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("creating consent directory: %w", err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return fmt.Errorf("recording consent: %w", err)
	}
	return nil
}

// WithdrawConsent removes the acceptance. Withdrawing nothing is not an error.
func WithdrawConsent(saltPath string) error {
	if err := os.Remove(ConsentPath(saltPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("withdrawing consent: %w", err)
	}
	return nil
}

// DeletionKey is the secret that authorises erasure of this installation's
// reporter id. It is an HMAC of the private salt, so it is stable and
// recoverable from the salt alone, and it is sent only to the erase endpoint.
func DeletionKey(saltPath string) (string, error) {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	salt, err := loadOrCreateSalt(saltPath)
	if err != nil {
		return "", err
	}
	return deletionKeyFor(salt), nil
}

func deletionKeyFor(salt []byte) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(deletionLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeletionVerifier is what the service stores instead of the key: the hex
// SHA-256 of the key string, matching the service's own derivation. The service
// holds a hash, so nothing it keeps can be replayed to erase anyone.
func DeletionVerifier(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Identity is this installation's reporter id and deletion key.
type Identity struct {
	ReporterID  string
	DeletionKey string
}

// ExistingIdentity derives the identity from an existing salt and reports
// found=false, creating nothing, when there is none. Erasure uses it: an
// installation that never had a salt never reported, and minting one just to
// ask the service to forget it would be absurd.
func ExistingIdentity(saltPath string) (id Identity, found bool, err error) {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	salt, err := os.ReadFile(saltPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Identity{}, false, nil
	case err != nil:
		return Identity{}, false, fmt.Errorf("reading reporter salt: %w", err)
	case len(salt) < 32:
		return Identity{}, false, nil
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(reporterLabel))
	return Identity{
		ReporterID:  hex.EncodeToString(mac.Sum(nil)),
		DeletionKey: deletionKeyFor(salt),
	}, true, nil
}
