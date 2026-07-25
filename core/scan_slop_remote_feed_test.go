package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
	"github.com/nox-hq/nox/core/findings"
)

// signedFeedJSON builds and signs a feed flagging the given entries.
func signedFeedJSON(t *testing.T, priv ed25519.PrivateKey, entries ...feed.Entry) []byte {
	t.Helper()
	f := &feed.Feed{
		SchemaVersion: feed.SchemaVersion,
		Version:       "remote-2026.07.25",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       entries,
	}
	if err := f.Sign(priv, "test-key"); err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestScanRemoteSignedFeedFiresSLOP002 proves the full remote trust chain from
// the consumer's side: nox fetches a signed feed over HTTP, verifies its
// signature against a pinned public key, and fires SLOP-002 — all without
// altering the SLOP-001 baseline.
func TestScanRemoteSignedFeedFiresSLOP002(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := signedFeedJSON(t, priv, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "unregistered high-risk", VerifiedAt: "2026-07-25",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	root := writeProject(t, map[string]string{
		"requirements.txt": "flask\n",
		"app.py":           "import flask\nimport openai_utils\n",
	})
	// Pin the publisher's public key on disk and require a signature.
	writeProjFile(t, root, "keys/slopfeed.pub.pem", feed.EncodePublicKeyPEM(pub))
	writeProjFile(t, root, ".nox.yaml",
		"scan:\n  slop:\n    feed: "+srv.URL+"\n    require_signature: true\n"+
			"    signature_key_path: keys/slopfeed.pub.pem\n"+
			"    cache_dir: .nox/slopfeed-cache\n")

	res, err := RunScanContext(context.Background(), root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := countRule(res, "SLOP-001"); got != 1 {
		t.Fatalf("expected 1 SLOP-001, got %d", got)
	}
	if got := countRule(res, "SLOP-002"); got != 1 {
		t.Fatalf("expected 1 SLOP-002 from the signed remote feed, got %d", got)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "SLOP-002" && f.Severity != findings.SeverityHigh {
			t.Errorf("critical-tier predictive finding should be High, got %q", f.Severity)
		}
	}
	// No degradation: the feed verified cleanly.
	for _, d := range res.Degradations {
		if d.Kind == "slop_feed" {
			t.Fatalf("unexpected slop_feed degradation on a valid signed feed: %+v", d)
		}
	}
}

// TestScanRemoteFeedCachedServesOffline proves that after one successful fetch,
// a subsequent offline scan is served from the verified cache with no network.
func TestScanRemoteFeedCachedServesOffline(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := signedFeedJSON(t, priv, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
	})
	var down bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	root := writeProject(t, map[string]string{"app.py": "import openai_utils\n"})
	writeProjFile(t, root, "keys/slopfeed.pub.pem", feed.EncodePublicKeyPEM(pub))
	writeProjFile(t, root, ".nox.yaml",
		"scan:\n  slop:\n    feed: "+srv.URL+"\n    require_signature: true\n"+
			"    signature_key_path: keys/slopfeed.pub.pem\n"+
			"    cache_dir: .nox/slopfeed-cache\n")

	// Prime the cache online.
	if _, err := RunScanContext(context.Background(), root, ScanOptions{}); err != nil {
		t.Fatalf("prime scan: %v", err)
	}
	// Take the server down AND scan offline: must be served from cache.
	down = true
	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("offline scan: %v", err)
	}
	if got := countRule(res, "SLOP-002"); got != 1 {
		t.Fatalf("offline cached feed should still fire SLOP-002, got %d", got)
	}
}

// TestScanRemoteTamperedFeedFailsClosed proves a MITM-tampered remote feed is
// rejected: no SLOP-002, a visible degradation, SLOP-001 intact, no crash.
func TestScanRemoteTamperedFeedFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := signedFeedJSON(t, priv, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
	})
	// Attacker mutates an entry to inject a name, invalidating the digest.
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["entries"].([]any)[0].(map[string]any)["name"] = "attacker-injected"
	tampered, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tampered)
	}))
	defer srv.Close()

	root := writeProject(t, map[string]string{"app.py": "import openai_utils\n"})
	writeProjFile(t, root, "keys/slopfeed.pub.pem", feed.EncodePublicKeyPEM(pub))
	writeProjFile(t, root, ".nox.yaml",
		"scan:\n  slop:\n    feed: "+srv.URL+"\n    require_signature: true\n"+
			"    signature_key_path: keys/slopfeed.pub.pem\n"+
			"    cache_dir: .nox/slopfeed-cache\n")

	res, err := RunScanContext(context.Background(), root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan must not crash on a tampered feed: %v", err)
	}
	if got := countRule(res, "SLOP-002"); got != 0 {
		t.Fatalf("tampered feed must yield no SLOP-002, got %d", got)
	}
	if got := countRule(res, "SLOP-001"); got != 1 {
		t.Fatalf("SLOP-001 baseline must be intact, got %d", got)
	}
	var degraded bool
	for _, d := range res.Degradations {
		if d.Kind == "slop_feed" {
			degraded = true
		}
	}
	if !degraded {
		t.Fatalf("a tampered remote feed must record a slop_feed degradation")
	}
}

// TestScanRemoteWrongIdentityFeedRejected proves a feed signed by a DIFFERENT
// key (a forged identity) is rejected even though it is internally consistent.
func TestScanRemoteWrongIdentityFeedRejected(t *testing.T) {
	// The publisher we pin.
	pinnedPub, _, _ := ed25519.GenerateKey(nil)
	// The attacker signs with their own key over a valid digest.
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	body := signedFeedJSON(t, attackerPriv, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	root := writeProject(t, map[string]string{"app.py": "import openai_utils\n"})
	writeProjFile(t, root, "keys/slopfeed.pub.pem", feed.EncodePublicKeyPEM(pinnedPub))
	writeProjFile(t, root, ".nox.yaml",
		"scan:\n  slop:\n    feed: "+srv.URL+"\n    require_signature: true\n"+
			"    signature_key_path: keys/slopfeed.pub.pem\n"+
			"    cache_dir: .nox/slopfeed-cache\n")

	res, err := RunScanContext(context.Background(), root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := countRule(res, "SLOP-002"); got != 0 {
		t.Fatalf("feed signed by a non-pinned identity must be rejected, got %d SLOP-002", got)
	}
	var degraded bool
	for _, d := range res.Degradations {
		if d.Kind == "slop_feed" {
			degraded = true
		}
	}
	if !degraded {
		t.Fatalf("wrong-identity feed must record a slop_feed degradation")
	}
}

// TestScanRemoteUnsignedFeedWithRequireSignatureRejected proves an unsigned feed
// is rejected when require_signature is set.
func TestScanRemoteUnsignedFeedWithRequireSignatureRejected(t *testing.T) {
	// Build an UNSIGNED but digest-valid feed.
	f := &feed.Feed{
		SchemaVersion: feed.SchemaVersion,
		Version:       "unsigned",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries: []feed.Entry{{
			Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
			Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
		}},
	}
	f.SetDigest()
	body, _ := json.Marshal(f)
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	root := writeProject(t, map[string]string{"app.py": "import openai_utils\n"})
	writeProjFile(t, root, "keys/slopfeed.pub.pem", feed.EncodePublicKeyPEM(pub))
	writeProjFile(t, root, ".nox.yaml",
		"scan:\n  slop:\n    feed: "+srv.URL+"\n    require_signature: true\n"+
			"    signature_key_path: keys/slopfeed.pub.pem\n"+
			"    cache_dir: .nox/slopfeed-cache\n")

	res, err := RunScanContext(context.Background(), root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := countRule(res, "SLOP-002"); got != 0 {
		t.Fatalf("unsigned feed under require_signature must be rejected, got %d", got)
	}
}

// writeFile writes a single file under root, creating parent dirs.
func writeProjFile(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
