package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// A session is what the CLI uses instead of the shared operator token.
//
// The token authorises every administrative action, never expires and belongs
// to no one. A session belongs to a person, carries their second factor, and
// can be revoked for them alone — which is the difference between an audit
// trail that names someone and one that says "whoever had the secret".

// session is what `nox intel login` stores.
type session struct {
	Endpoint  string `json:"endpoint"`
	Email     string `json:"email"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// keychainService is the entry name in the macOS keychain.
const keychainService = "nox-intel-session"

// sessionPath is the fallback store, used where there is no keychain.
func sessionPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "nox", "intel-session.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".nox-intel-session.json"
	}
	return filepath.Join(home, ".config", "nox", "intel-session.json")
}

// saveSession stores the session, preferring the OS keychain.
//
// A session token is a bearer credential: anything holding it is the operator
// until it expires. On macOS the keychain keeps it out of the filesystem
// entirely; elsewhere a 0600 file in the user's config directory is the honest
// second best, and the file is written with O_TRUNC so a shorter token cannot
// leave the tail of a longer one behind.
func saveSession(s session) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" && keychainAvailable() {
		if err := keychainStore(string(blob)); err == nil {
			return nil
		}
		// Fall through to the file. A keychain that refuses is a reason to warn,
		// not a reason to leave the operator unable to sign in.
		fmt.Fprintf(os.Stderr, "warning: could not use the keychain; storing the session in %s instead\n", sessionPath())
	}
	p := sessionPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// loadSession returns the stored session, if there is one.
func loadSession() (session, bool) {
	var s session
	if runtime.GOOS == "darwin" && keychainAvailable() {
		if raw, err := keychainFetch(); err == nil && raw != "" {
			if json.Unmarshal([]byte(raw), &s) == nil && s.Token != "" {
				return s, true
			}
		}
	}
	blob, err := os.ReadFile(sessionPath())
	if err != nil {
		return session{}, false
	}
	if json.Unmarshal(blob, &s) != nil || s.Token == "" {
		return session{}, false
	}
	return s, true
}

// clearSession removes the stored session from both stores.
//
// Both, unconditionally: a token left in the file after a keychain logout is a
// live credential that the operator believes they have destroyed.
func clearSession() {
	if runtime.GOOS == "darwin" && keychainAvailable() {
		_ = exec.Command("security", "delete-generic-password", "-s", keychainService).Run()
	}
	_ = os.Remove(sessionPath())
}

func keychainAvailable() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

func keychainStore(blob string) error {
	// -U updates in place, so signing in twice does not leave two entries with
	// only one of them current.
	cmd := exec.Command("security", "add-generic-password",
		"-a", os.Getenv("USER"), "-s", keychainService, "-U", "-w", blob)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func keychainFetch() (string, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-a", os.Getenv("USER"), "-s", keychainService, "-w").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// sessionExpired reports whether a stored session is past its stated expiry.
//
// Checked locally so `nox intel whoami` can say "expired" rather than making a
// request that fails with a 401 the operator then has to interpret. The server
// remains the authority; this is a courtesy, not a security boundary.
func sessionExpired(s session) bool {
	if s.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(t)
}
