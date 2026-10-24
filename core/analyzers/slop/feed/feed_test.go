package feed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/slopfeed"
)

// The format's own behaviour (digest, tampering, malformed input, signature
// policy) is tested in github.com/nox-hq/nox-core/slopfeed. These tests cover
// only what this package adds: reading a file and the bundled feed.

// sampleEntries returns a small, deterministic entry set for tests.
func sampleEntries() []slopfeed.Entry {
	return []slopfeed.Entry{
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
func buildFeed(t *testing.T) *slopfeed.Feed {
	t.Helper()
	f := &slopfeed.Feed{
		SchemaVersion: slopfeed.SchemaVersion,
		Version:       "2026.07.25",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       sampleEntries(),
	}
	if err := f.SetDigest(); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadFromFile(t *testing.T) {
	f := buildFeed(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, mustJSON(t, f), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, slopfeed.VerifyOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", loaded.Len())
	}
}

func TestLoadMissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json"), slopfeed.VerifyOptions{}); err == nil {
		t.Fatal("loading a missing file must fail")
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
