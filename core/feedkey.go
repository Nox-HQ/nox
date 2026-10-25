package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // the official feed key is embedded
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/slopfeed"
)

// BuiltinFeedKeyID names the official NOX Intelligence feed signing key that is
// built into nox. Both signed feeds (the predictive slopsquat feed and the MCP
// advisory feed) are signed by it.
const BuiltinFeedKeyID = "slopfeed-key-v1"

// builtinFeedKeyPEM is the key as the service publishes it at
// /v1/feeds/slopsquat.pub.pem and /v1/feeds/mcp.pub.pem. It lives in one place:
// both feed consumers resolve their verifier from it.
//
//go:embed feedkey/slopfeed-key-v1.pem
var builtinFeedKeyPEM []byte

// feedKeyProbeTimeout bounds the one request made to learn which key the
// service signs with, after a feed failed verification under the built-in key.
const feedKeyProbeTimeout = 10 * time.Second

// maxFeedKeySize bounds a served public key; a real one is under 200 bytes.
const maxFeedKeySize = 4096

// BuiltinFeedKeyFingerprint is the fingerprint of the built-in key: "sha256:"
// and the hex SHA-256 of the raw 32-byte Ed25519 public key. The same
// fingerprint is computed for a project-pinned key and for the key the service
// serves, so the three can be compared whatever PEM form each arrived in.
func BuiltinFeedKeyFingerprint() string {
	fp, err := feedKeyFingerprint(builtinFeedKeyPEM)
	if err != nil { // the embedded key is validated by a test; unreachable in a release
		return "unavailable: " + err.Error()
	}
	return fp
}

// feedKey is the key a feed is verified under and where it came from, so the
// output can say which one verified.
type feedKey struct {
	verify      slopfeed.SignatureVerifier
	builtin     bool
	fingerprint string
	// label is how output names the key: "built-in key slopfeed-key-v1 (...)" or
	// "project key keys/x.pem (...)".
	label string
}

// source is the short machine-readable provenance recorded on findings.
func (k feedKey) source() string {
	if k.builtin {
		return "built-in:" + BuiltinFeedKeyID
	}
	return "project:" + k.fingerprint
}

// resolveFeedKey returns the project's pinned key when keyPath is set (a
// configured key always wins) and the built-in key otherwise.
func resolveFeedKey(target, keyPath string) (feedKey, error) {
	if keyPath == "" {
		return builtinFeedKey()
	}
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(scanRootDir(target), keyPath)
	}
	data, err := os.ReadFile(keyPath) // #nosec G304 -- operator-configured key path
	if err != nil {
		return feedKey{}, fmt.Errorf("reading %s: %w", keyPath, err)
	}
	v, err := slopfeed.PEMEd25519Verifier(data)
	if err != nil {
		return feedKey{}, fmt.Errorf("parsing %s: %w", keyPath, err)
	}
	fp, err := feedKeyFingerprint(data)
	if err != nil {
		return feedKey{}, fmt.Errorf("parsing %s: %w", keyPath, err)
	}
	return feedKey{verify: v, fingerprint: fp, label: fmt.Sprintf("project key %s (%s)", keyPath, fp)}, nil
}

func builtinFeedKey() (feedKey, error) {
	v, err := slopfeed.PEMEd25519Verifier(builtinFeedKeyPEM)
	if err != nil {
		return feedKey{}, fmt.Errorf("the built-in feed key is unusable: %w", err)
	}
	fp, err := feedKeyFingerprint(builtinFeedKeyPEM)
	if err != nil {
		return feedKey{}, err
	}
	return feedKey{verify: v, builtin: true, fingerprint: fp,
		label: fmt.Sprintf("built-in key %s (%s)", BuiltinFeedKeyID, fp)}, nil
}

// feedKeyFingerprint hashes the raw public key, accepting both PEM forms
// slopfeed.PEMEd25519Verifier does.
func feedKeyFingerprint(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("no PEM block in public key")
	}
	raw := block.Bytes
	if len(raw) != ed25519.PublicKeySize {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("unexpected public key length: %d", len(block.Bytes))
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return "", fmt.Errorf("public key is not Ed25519 (got %T)", parsed)
		}
		raw = pub
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// isFeedVerificationFailure reports a feed that was received and did not verify,
// as opposed to one that could not be fetched.
func isFeedVerificationFailure(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "signature") || strings.Contains(m, "unsigned") || strings.Contains(m, "no signature")
}

// servedKeyFingerprint asks the service which key it signs with: the
// <feed>.pub.pem it publishes beside the feed. It is called only after a feed
// failed verification under the built-in key, to tell a rotated key apart from a
// tampered feed. It never changes what is trusted: the answer is reported, not
// used.
func servedKeyFingerprint(ctx context.Context, feedURL string, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: feedKeyProbeTimeout}
	}
	ctx, cancel := context.WithTimeout(ctx, feedKeyProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(feedURL, "/")+".pub.pem", http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "nox-feedkey-client")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedKeySize))
	if err != nil {
		return "", err
	}
	return feedKeyFingerprint(body)
}

// explainFeedFailure turns a verification failure into the message the operator
// reads. Under the built-in key it also checks, once, whether the service has
// rotated to a different key, and says so naming both fingerprints. It never
// accepts the served key.
func explainFeedFailure(ctx context.Context, key feedKey, feedURL string, offline bool, err error) string {
	base := fmt.Sprintf("%v", err)
	if !key.builtin || offline || !isFeedVerificationFailure(err) {
		return base
	}
	served, perr := servedKeyFingerprint(ctx, feedURL, nil)
	if perr != nil || served == key.fingerprint {
		return base + fmt.Sprintf(" (verified against the %s)", key.label)
	}
	return fmt.Sprintf("%v. The service now serves a different signing key (%s) than the one built into this nox (%s, %s): the key was probably rotated. nox does not trust a key the server hands it; upgrade nox, or review the new key and pin it with signature_key_path",
		err, served, BuiltinFeedKeyID, key.fingerprint)
}
