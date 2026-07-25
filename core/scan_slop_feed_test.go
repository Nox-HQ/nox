package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
	"github.com/nox-hq/nox/core/findings"
)

// writeProject writes files under a temp dir and returns the root.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func countRule(res *ScanResult, ruleID string) int {
	if res.Findings == nil {
		return 0
	}
	n := 0
	for _, f := range res.Findings.Findings() {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

func writeFeedFile(t *testing.T, dir, name string, entries ...feed.Entry) string {
	t.Helper()
	f := &feed.Feed{
		SchemaVersion: feed.SchemaVersion,
		Version:       "test-2026.07.25",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       entries,
	}
	f.SetDigest()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanDefaultSafeNoFeed proves that, with no slop.feed configured, the scan
// produces the exact same SLOP findings as before this feature existed: SLOP-001
// as usual and zero SLOP-002.
func TestScanDefaultSafeNoFeed(t *testing.T) {
	root := writeProject(t, map[string]string{
		"requirements.txt": "flask\n",
		"app.py":           "import flask\nimport openai_utils\n",
	})
	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := countRule(res, "SLOP-001"); got != 1 {
		t.Fatalf("expected 1 SLOP-001, got %d", got)
	}
	if got := countRule(res, "SLOP-002"); got != 0 {
		t.Fatalf("expected 0 SLOP-002 without a feed, got %d", got)
	}
}

// TestScanWithFeedAddsPredictiveOnly proves the feature is additive: enabling a
// feed adds SLOP-002 findings without changing the SLOP-001 baseline.
func TestScanWithFeedAddsPredictiveOnly(t *testing.T) {
	root := writeProject(t, map[string]string{
		"requirements.txt": "flask\n",
		"app.py":           "import flask\nimport openai_utils\n",
	})
	// Baseline (no feed).
	baseRes, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	baseSlop001 := countRule(baseRes, "SLOP-001")

	// Configure a feed that flags openai-utils, then re-scan.
	writeFeedFile(t, root, "slopfeed.json", feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "unregistered high-risk", VerifiedAt: "2026-07-25",
	})
	if err := os.WriteFile(filepath.Join(root, ".nox.yaml"),
		[]byte("scan:\n  slop:\n    feed: slopfeed.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	feedRes, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}

	if got := countRule(feedRes, "SLOP-001"); got != baseSlop001 {
		t.Fatalf("SLOP-001 baseline changed with feed on: was %d, now %d", baseSlop001, got)
	}
	if got := countRule(feedRes, "SLOP-002"); got != 1 {
		t.Fatalf("expected 1 SLOP-002 with feed on, got %d", got)
	}
	for _, f := range feedRes.Findings.Findings() {
		if f.RuleID == "SLOP-002" && f.Severity != findings.SeverityHigh {
			t.Errorf("critical-tier predictive finding should be High severity, got %q", f.Severity)
		}
	}
}

// TestScanTamperedFeedFailsClosed proves a tampered feed disables the predictive
// dimension (no SLOP-002) and records a degradation, without crashing the scan
// or altering the SLOP-001 baseline.
func TestScanTamperedFeedFailsClosed(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app.py": "import openai_utils\n",
	})
	path := writeFeedFile(t, root, "slopfeed.json", feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
	})
	// Tamper: flip a byte in an entry so the digest no longer matches.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["entries"].([]any)[0].(map[string]any)["name"] = "evil-swapped-name"
	tampered, _ := json.Marshal(m)
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".nox.yaml"),
		[]byte("scan:\n  slop:\n    feed: slopfeed.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan must not fail on a bad feed: %v", err)
	}
	if got := countRule(res, "SLOP-002"); got != 0 {
		t.Fatalf("tampered feed must yield no SLOP-002, got %d", got)
	}
	// The SLOP-001 baseline is unaffected.
	if got := countRule(res, "SLOP-001"); got != 1 {
		t.Fatalf("expected SLOP-001 baseline intact, got %d", got)
	}
	// A degradation must be visible so the missing predictive coverage is not
	// mistaken for "nothing high-risk found".
	var found bool
	for _, d := range res.Degradations {
		if d.Kind == "slop_feed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a slop_feed degradation to be recorded, got %+v", res.Degradations)
	}
}

// TestScanBundledFeedLoads proves the bundled feed wires end to end.
func TestScanBundledFeedLoads(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app.py":    "import openai_utils\n",
		".nox.yaml": "scan:\n  slop:\n    feed: bundled\n",
	})
	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	// openai-utils is in the bundled feed, so it must flag predictively.
	if got := countRule(res, "SLOP-002"); got < 1 {
		t.Fatalf("expected the bundled feed to flag openai_utils, got %d SLOP-002", got)
	}
}
