package feed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleEntries returns a small, deterministic entry set for tests.
func sampleEntries() []Entry {
	return []Entry{
		{
			Name:       "openai-utils",
			Ecosystem:  "pypi",
			Pattern:    "obvious",
			Risk:       0.82,
			Tier:       "critical",
			Reason:     "unregistered and high-likelihood hallucination",
			VerifiedAt: "2026-07-25",
		},
		{
			Name:       "axios-retry-async",
			Ecosystem:  "npm",
			Pattern:    "obvious",
			Risk:       0.82,
			Tier:       "critical",
			Reason:     "unregistered and high-likelihood hallucination",
			VerifiedAt: "2026-07-25",
		},
	}
}

// buildFeed assembles a Feed with a correct digest over sampleEntries.
func buildFeed(t *testing.T) *Feed {
	t.Helper()
	f := &Feed{
		SchemaVersion: SchemaVersion,
		Version:       "2026.07.25",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       sampleEntries(),
	}
	f.SetDigest()
	return f
}

func TestFeedRoundTripAndDigestVerifies(t *testing.T) {
	f := buildFeed(t)
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	loaded, err := Parse(data, VerifyOptions{})
	if err != nil {
		t.Fatalf("parse valid feed: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", loaded.Len())
	}
	if got := loaded.Digest(); !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("digest not sha256-prefixed: %q", got)
	}

	// Lookup is normalized: PyPI names compare under PEP 503 canonical form.
	if _, ok := loaded.Lookup("pypi", "OpenAI_Utils"); !ok {
		t.Errorf("expected normalized PyPI lookup to hit openai-utils")
	}
	if _, ok := loaded.Lookup("npm", "axios-retry-async"); !ok {
		t.Errorf("expected npm lookup to hit axios-retry-async")
	}
	if _, ok := loaded.Lookup("pypi", "requests"); ok {
		t.Errorf("did not expect a hit for a name absent from the feed")
	}
}

func TestTamperedEntriesRejected(t *testing.T) {
	f := buildFeed(t)
	// Tamper: mutate an entry AFTER the digest was computed. A consumer must
	// reject this — the digest no longer covers the content.
	f.Entries[0].Name = "evil-injected-name"
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Parse(data, VerifyOptions{}); err == nil {
		t.Fatalf("expected tampered feed to be rejected, got nil error")
	}
}

func TestMalformedFeedFailsClosedNoPanic(t *testing.T) {
	cases := map[string][]byte{
		"not json":        []byte("{not json"),
		"empty":           []byte(""),
		"missing digest":  mustJSON(t, &Feed{SchemaVersion: SchemaVersion, Entries: sampleEntries()}),
		"bad schema":      mustJSON(t, &Feed{SchemaVersion: "bogus/v9", Digest: "sha256:00", Entries: sampleEntries()}),
		"garbage digest":  mustJSON(t, &Feed{SchemaVersion: SchemaVersion, Digest: "not-a-digest", Entries: sampleEntries()}),
		"truncated bytes": []byte(`{"schema_version":"slopsquat-blocklist/v1","digest":`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			// Must never panic and must return an error (fail closed).
			loaded, err := Parse(data, VerifyOptions{})
			if err == nil {
				t.Fatalf("expected error for %s, got a loaded feed", name)
			}
			if loaded != nil {
				t.Fatalf("expected nil loaded feed on error for %s", name)
			}
		})
	}
}

func TestSignatureVerificationHook(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := buildFeed(t)
	// Sign the canonical content (the same bytes the digest covers).
	content := CanonicalEntries(f.Entries)
	sig := ed25519.Sign(priv, content)
	f.Signature = &Signature{
		Algorithm: "ed25519",
		KeyID:     "test-key",
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	data := mustJSON(t, f)

	// A verifier that trusts our test public key accepts the feed.
	good := Ed25519Verifier(pub)
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: good}); err != nil {
		t.Fatalf("valid signature should verify: %v", err)
	}

	// A verifier with the wrong key must reject when a signature is required.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	bad := Ed25519Verifier(otherPub)
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: bad}); err == nil {
		t.Fatalf("signature under wrong key must be rejected")
	}

	// RequireSignature with no signature present must fail closed.
	unsigned := buildFeed(t)
	if _, err := Parse(mustJSON(t, unsigned), VerifyOptions{RequireSignature: true, Verifier: good}); err == nil {
		t.Fatalf("RequireSignature must reject an unsigned feed")
	}
}

func TestLoadFromFile(t *testing.T) {
	f := buildFeed(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, mustJSON(t, f), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", loaded.Len())
	}
}

func TestBundledFeedVerifies(t *testing.T) {
	loaded, err := Bundled()
	if err != nil {
		t.Fatalf("bundled feed must load and verify: %v", err)
	}
	if loaded.Len() == 0 {
		t.Fatalf("bundled feed should not be empty")
	}
	// Every bundled entry must carry the fields the consumer relies on.
	for _, e := range loaded.Feed.Entries {
		if e.Name == "" || (e.Ecosystem != "pypi" && e.Ecosystem != "npm") {
			t.Errorf("bundled entry malformed: %+v", e)
		}
		if e.Tier != "critical" && e.Tier != "high" && e.Tier != "medium" {
			t.Errorf("bundled entry has unexpected tier: %+v", e)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
