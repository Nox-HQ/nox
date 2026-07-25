package main

import (
	"testing"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

func TestGenerateIsDeterministic(t *testing.T) {
	a := generateCandidates()
	b := generateCandidates()
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("generation not deterministic in length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("generation not deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestGenerateNeverEmitsRealSeed(t *testing.T) {
	// A candidate that collides with a real, popular seed must be dropped — the
	// generator only ever proposes names that are NOT known-real packages.
	realSeeds := map[string]struct{}{}
	for _, n := range pypiSeeds {
		realSeeds["pypi\x00"+n] = struct{}{}
	}
	for _, n := range npmSeeds {
		realSeeds["npm\x00"+n] = struct{}{}
	}
	for _, c := range generateCandidates() {
		if _, isReal := realSeeds[c.ecosystem+"\x00"+c.name]; isReal {
			t.Errorf("candidate collides with a real seed: %s/%s", c.ecosystem, c.name)
		}
	}
}

func TestGeneratePriorsInRange(t *testing.T) {
	for _, c := range generateCandidates() {
		if c.prior < 0 || c.prior > 1 {
			t.Errorf("prior out of range for %s: %v", c.name, c.prior)
		}
		if c.ecosystem != "pypi" && c.ecosystem != "npm" {
			t.Errorf("unexpected ecosystem %q for %s", c.ecosystem, c.name)
		}
	}
}

func TestKnownSquattableNamesAreGenerated(t *testing.T) {
	// The names the research verified as squattable must actually be produced by
	// the generator model — otherwise the harness could never have found them.
	want := map[string]string{
		"openai-utils":      "pypi",
		"anthropic-async":   "pypi",
		"axios-retry-async": "npm",
		"numpys":            "pypi",
		"requests-sdk":      "pypi",
	}
	got := map[string]string{}
	for _, c := range generateCandidates() {
		got[c.name] = c.ecosystem
	}
	for name, eco := range want {
		if got[name] != eco {
			t.Errorf("expected generator to produce %s (%s); it did not", name, eco)
		}
	}
}

func TestScoreSquattableProducesValidFeedEntry(t *testing.T) {
	c := candidate{name: "openai-utils", ecosystem: "pypi", pattern: "obvious", prior: 0.78, reason: "obvious API name"}
	r := checkResult{name: c.name, ecosystem: c.ecosystem, verdict: unregistered}
	e, ok := scoreSquattable(c, r, "2026-07-25")
	if !ok {
		t.Fatal("expected an unregistered high-prior candidate to score squattable")
	}
	if e.Tier != feed.TierCritical && e.Tier != feed.TierHigh && e.Tier != feed.TierMedium {
		t.Errorf("unexpected tier %q", e.Tier)
	}
	if e.VerifiedAt != "2026-07-25" {
		t.Errorf("verified_at not stamped: %q", e.VerifiedAt)
	}
}

func TestLowRiskCandidateNotWritten(t *testing.T) {
	// A composition name with a low prior falls below the medium tier and must
	// not be written to the feed even when unregistered.
	c := candidate{name: "requests-x", ecosystem: "pypi", pattern: "composition", prior: 0.40}
	r := checkResult{verdict: unregistered}
	if _, ok := scoreSquattable(c, r, "2026-07-25"); ok {
		t.Fatal("a sub-medium-risk candidate must not be written to the feed")
	}
}
