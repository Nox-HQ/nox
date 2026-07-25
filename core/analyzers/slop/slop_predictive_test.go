package slop

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
	"github.com/nox-hq/nox/core/findings"
)

// loadedFeed builds an in-memory verified feed with the given entries.
func loadedFeed(t *testing.T, entries ...feed.Entry) *feed.Loaded {
	t.Helper()
	f := &feed.Feed{
		SchemaVersion: feed.SchemaVersion,
		Version:       "test",
		GeneratedAt:   "2026-07-25T00:00:00Z",
		Source:        "test",
		Entries:       entries,
	}
	f.SetDigest()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := feed.Parse(data, feed.VerifyOptions{})
	if err != nil {
		t.Fatalf("parse test feed: %v", err)
	}
	return loaded
}

func scanWith(t *testing.T, a *Analyzer, files map[string]string) []findings.Finding {
	t.Helper()
	arts := writeTree(t, files)
	fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

func ruleIDs(fs []findings.Finding, ruleID string) []findings.Finding {
	var out []findings.Finding
	for i := range fs {
		if fs[i].RuleID == ruleID {
			out = append(out, fs[i])
		}
	}
	return out
}

// TestNoFeedBaselineUnchanged proves the default-safe property: with NO feed
// configured, the analyzer behaves exactly as today — SLOP-001 as before, and
// no SLOP-002 predictive findings, even for an import that a feed WOULD flag.
func TestNoFeedBaselineUnchanged(t *testing.T) {
	files := map[string]string{
		"requirements.txt": "flask\n",
		"app.py":           "import flask\nimport openai_utils\n",
	}
	base := scanWith(t, NewAnalyzer(), files)

	// SLOP-001 fires for the undeclared import, as it always has.
	if got := ruleIDs(base, "SLOP-001"); len(got) != 1 || got[0].Metadata["package"] != "openai_utils" {
		t.Fatalf("expected exactly one SLOP-001 for openai_utils, got %+v", got)
	}
	// No predictive findings without a feed.
	if got := ruleIDs(base, "SLOP-002"); len(got) != 0 {
		t.Fatalf("expected no SLOP-002 without a feed, got %+v", got)
	}
}

// TestFeedMatchEmitsPredictiveFinding: with a feed loaded, an import whose name
// matches a high-risk entry raises a distinct SLOP-002 predictive finding, and
// the underlying SLOP-001 baseline finding is untouched.
func TestFeedMatchEmitsPredictiveFinding(t *testing.T) {
	fd := loadedFeed(t, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "unregistered high-risk", VerifiedAt: "2026-07-25",
	})
	files := map[string]string{
		"requirements.txt": "flask\n",
		// PEP 503: `openai_utils` import normalizes to the feed's `openai-utils`.
		"app.py": "import flask\nimport openai_utils\n",
	}
	got := scanWith(t, NewAnalyzer(WithFeed(fd)), files)

	pred := ruleIDs(got, "SLOP-002")
	if len(pred) != 1 {
		t.Fatalf("expected one SLOP-002, got %+v", pred)
	}
	p := pred[0]
	if p.Severity != findings.SeverityHigh {
		t.Errorf("critical-tier target should map to High severity, got %q", p.Severity)
	}
	if p.Metadata["tier"] != "critical" || p.Metadata["package"] != "openai_utils" {
		t.Errorf("predictive metadata missing/wrong: %+v", p.Metadata)
	}
	if p.Metadata["feed_version"] != "test" {
		t.Errorf("expected feed_version metadata, got %+v", p.Metadata)
	}
	// The baseline SLOP-001 finding is still present and unchanged.
	if base := ruleIDs(got, "SLOP-001"); len(base) != 1 || base[0].Severity != findings.SeverityMedium {
		t.Errorf("SLOP-001 baseline changed: %+v", base)
	}
}

// TestPredictiveFiresOnDeclaredPackage: the dangerous middle case. A developer
// has DECLARED (installed) a name that the feed knows is a squattable target.
// SLOP-001 stays silent (the import resolves to a manifest entry), but the
// predictive rule must still warn — they may have installed the squat.
func TestPredictiveFiresOnDeclaredPackage(t *testing.T) {
	fd := loadedFeed(t, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "unregistered high-risk", VerifiedAt: "2026-07-25",
	})
	files := map[string]string{
		"requirements.txt": "openai-utils\n",
		"app.py":           "import openai_utils\n",
	}
	got := scanWith(t, NewAnalyzer(WithFeed(fd)), files)

	if base := ruleIDs(got, "SLOP-001"); len(base) != 0 {
		t.Fatalf("SLOP-001 must stay silent for a declared package, got %+v", base)
	}
	if pred := ruleIDs(got, "SLOP-002"); len(pred) != 1 {
		t.Fatalf("SLOP-002 must fire for a declared squat target, got %+v", pred)
	}
}

// TestPredictiveNoMatchNoFinding: an ordinary hallucinated import not in the
// feed gets only the baseline SLOP-001, never a predictive finding.
func TestPredictiveNoMatchNoFinding(t *testing.T) {
	fd := loadedFeed(t, feed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "x", VerifiedAt: "2026-07-25",
	})
	files := map[string]string{"app.py": "import some_random_phantom_pkg\n"}
	got := scanWith(t, NewAnalyzer(WithFeed(fd)), files)
	if pred := ruleIDs(got, "SLOP-002"); len(pred) != 0 {
		t.Fatalf("expected no SLOP-002 for a non-feed name, got %+v", pred)
	}
	if base := ruleIDs(got, "SLOP-001"); len(base) != 1 {
		t.Fatalf("expected SLOP-001 for the phantom import, got %+v", base)
	}
}

// TestPredictiveSeverityByTier checks the tier->severity mapping.
func TestPredictiveSeverityByTier(t *testing.T) {
	cases := []struct {
		tier string
		want findings.Severity
	}{
		{"critical", findings.SeverityHigh},
		{"high", findings.SeverityMedium},
		{"medium", findings.SeverityLow},
	}
	for _, tc := range cases {
		fd := loadedFeed(t, feed.Entry{
			Name: "ghostpkg", Ecosystem: "pypi", Pattern: "typo",
			Risk: 0.7, Tier: tc.tier, Reason: "x", VerifiedAt: "2026-07-25",
		})
		got := scanWith(t, NewAnalyzer(WithFeed(fd)), map[string]string{"a.py": "import ghostpkg\n"})
		pred := ruleIDs(got, "SLOP-002")
		if len(pred) != 1 || pred[0].Severity != tc.want {
			t.Errorf("tier %s: expected severity %s, got %+v", tc.tier, tc.want, pred)
		}
	}
}

// TestPredictiveDedupPerFile: multiple imports of the same feed name in one
// file yield a single predictive finding.
func TestPredictiveDedupPerFile(t *testing.T) {
	fd := loadedFeed(t, feed.Entry{
		Name: "ghostpkg", Ecosystem: "pypi", Pattern: "typo",
		Risk: 0.7, Tier: "high", Reason: "x", VerifiedAt: "2026-07-25",
	})
	files := map[string]string{"a.py": "import ghostpkg\nimport ghostpkg\nfrom ghostpkg import x\n"}
	got := scanWith(t, NewAnalyzer(WithFeed(fd)), files)
	if pred := ruleIDs(got, "SLOP-002"); len(pred) != 1 {
		t.Fatalf("expected one deduplicated SLOP-002, got %d", len(pred))
	}
}

// TestRuleSetIncludesPredictive ensures SLOP-002 is registered in the rule set.
func TestRuleSetIncludesPredictive(t *testing.T) {
	var found bool
	for _, r := range NewAnalyzer().Rules().Rules() {
		if r.ID == "SLOP-002" {
			found = true
		}
	}
	if !found {
		t.Fatal("SLOP-002 must be registered in the rule set")
	}
}
