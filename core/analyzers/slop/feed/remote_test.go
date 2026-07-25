package feed

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// signedFeedBytes builds a feed over sampleEntries, signs it with priv, and
// returns the JSON bytes a server would serve.
func signedFeedBytes(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	f := &Feed{
		SchemaVersion: SchemaVersion,
		Version:       "2026.07.25",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       sampleEntries(),
	}
	if err := f.Sign(priv, "test-key"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return mustJSON(t, f)
}

// countingServer serves body and records how many requests it received.
func countingServer(body []byte, hits *int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(hits, 1)
		_, _ = w.Write(body)
	}))
}

func TestLoadRemoteValidSignatureLoads(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var hits int64
	srv := countingServer(signedFeedBytes(t, priv), &hits)
	defer srv.Close()

	loaded, err := LoadRemote(context.Background(), RemoteOptions{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		TTL:      time.Hour,
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	})
	if err != nil {
		t.Fatalf("valid signed remote feed must load: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", loaded.Len())
	}
	if _, ok := loaded.Lookup("pypi", "openai-utils"); !ok {
		t.Fatalf("expected openai-utils in the loaded feed")
	}
}

func TestLoadRemoteWrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	var hits int64
	srv := countingServer(signedFeedBytes(t, priv), &hits)
	defer srv.Close()

	loaded, err := LoadRemote(context.Background(), RemoteOptions{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(otherPub)},
	})
	if err == nil {
		t.Fatalf("feed signed by a different key must be rejected")
	}
	if loaded != nil {
		t.Fatalf("expected nil loaded feed on rejection")
	}
}

func TestLoadRemoteTamperedDigestRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := signedFeedBytes(t, priv)
	// Tamper: mutate an entry after signing so the digest no longer matches.
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["entries"].([]any)[0].(map[string]any)["name"] = "evil-injected"
	tampered := mustJSON(t, m)
	var hits int64
	srv := countingServer(tampered, &hits)
	defer srv.Close()

	loaded, err := LoadRemote(context.Background(), RemoteOptions{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	})
	if err == nil {
		t.Fatalf("tampered feed must be rejected (digest mismatch)")
	}
	if loaded != nil {
		t.Fatalf("expected nil loaded feed on tamper")
	}
}

func TestLoadRemoteRequireSignatureUnsignedRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	// Serve an UNSIGNED (but digest-valid) feed.
	f := buildFeed(t)
	var hits int64
	srv := countingServer(mustJSON(t, f), &hits)
	defer srv.Close()

	_, err := LoadRemote(context.Background(), RemoteOptions{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	})
	if err == nil {
		t.Fatalf("require_signature must reject an unsigned remote feed")
	}
}

func TestLoadRemoteFreshCacheAvoidsNetwork(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var hits int64
	srv := countingServer(signedFeedBytes(t, priv), &hits)
	defer srv.Close()

	dir := t.TempDir()
	opts := RemoteOptions{
		URL:      srv.URL,
		CacheDir: dir,
		TTL:      time.Hour,
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	}
	if _, err := LoadRemote(context.Background(), opts); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("expected exactly 1 network hit on first load, got %d", got)
	}
	// Second load within TTL must be served from the verified cache: no network.
	if _, err := LoadRemote(context.Background(), opts); err != nil {
		t.Fatalf("second load: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("fresh cache must avoid the network: expected 1 hit total, got %d", got)
	}
}

func TestLoadRemoteOfflineUsesCacheNeverNetwork(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var hits int64
	srv := countingServer(signedFeedBytes(t, priv), &hits)
	defer srv.Close()

	dir := t.TempDir()
	base := RemoteOptions{
		URL:      srv.URL,
		CacheDir: dir,
		TTL:      time.Hour,
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	}
	// Prime the cache once online.
	if _, err := LoadRemote(context.Background(), base); err != nil {
		t.Fatalf("prime: %v", err)
	}
	primed := atomic.LoadInt64(&hits)

	// Now go offline with TTL=0 (would normally force a refetch): must still be
	// served from cache and must not touch the network.
	offline := base
	offline.Offline = true
	offline.TTL = 0
	loaded, err := LoadRemote(context.Background(), offline)
	if err != nil {
		t.Fatalf("offline load from cache must succeed: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected cached feed with 2 entries, got %d", loaded.Len())
	}
	if got := atomic.LoadInt64(&hits); got != primed {
		t.Fatalf("offline mode must not touch the network: hits went %d -> %d", primed, got)
	}
}

func TestLoadRemoteOfflineWithNoCacheFailsClosed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := LoadRemote(context.Background(), RemoteOptions{
		URL:      "https://feeds.example.com/slopfeed.json",
		CacheDir: t.TempDir(),
		Offline:  true,
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	})
	if err == nil {
		t.Fatalf("offline with no cache must fail closed")
	}
}

func TestLoadRemoteFetchErrorFallsBackToCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good := signedFeedBytes(t, priv)
	var serverDown atomic.Bool
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		if serverDown.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(good)
	}))
	defer srv.Close()

	dir := t.TempDir()
	base := RemoteOptions{
		URL:      srv.URL,
		CacheDir: dir,
		TTL:      time.Hour,
		Verify:   VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)},
	}
	if _, err := LoadRemote(context.Background(), base); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Server now fails; force a refetch (TTL=0). Must fall back to the verified
	// cache rather than failing the load.
	serverDown.Store(true)
	stale := base
	stale.TTL = 0
	loaded, err := LoadRemote(context.Background(), stale)
	if err != nil {
		t.Fatalf("fetch error must fall back to cache: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected cached feed, got %d entries", loaded.Len())
	}
}

func TestLoadRemoteRejectsNonHTTPScheme(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "ftp://x/y", "/local/path", ""} {
		if _, err := LoadRemote(context.Background(), RemoteOptions{URL: u, CacheDir: t.TempDir()}); err == nil {
			t.Fatalf("scheme %q must be rejected", u)
		}
	}
}

func TestSignRoundTripsThroughPEMVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := buildFeed(t)
	if err := f.Sign(priv, "kid-1"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	data := mustJSON(t, f)

	// The public key the signer embedded must be usable to build a verifier that
	// accepts the feed — and it must be the SAME key material as pub.
	verifier := Ed25519Verifier(pub)
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: verifier}); err != nil {
		t.Fatalf("signed feed must verify under the signer's public key: %v", err)
	}
	// A PEM verifier built from the embedded public key must also accept it.
	pemVerifier, err := PEMEd25519Verifier([]byte(f.Signature.PublicKeyPEM))
	if err != nil {
		t.Fatalf("PEMEd25519Verifier from embedded key: %v", err)
	}
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: pemVerifier}); err != nil {
		t.Fatalf("signed feed must verify under a PEM verifier from its embedded key: %v", err)
	}
}
