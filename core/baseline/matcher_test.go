package baseline

import (
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

func entry(fp string) Entry {
	return Entry{Fingerprint: fp, RuleID: "IAC-018", FilePath: "w.yml", CreatedAt: time.Now()}
}

func finding(fp string, line int) findings.Finding {
	return findings.Finding{
		RuleID:      "IAC-018",
		Fingerprint: fp,
		Severity:    findings.SeverityMedium,
		Location:    findings.Location{FilePath: "w.yml", StartLine: line},
	}
}

func loaded(entries ...Entry) *Baseline {
	b := &Baseline{SchemaVersion: schemaVersion, Entries: entries}
	b.buildIndex()
	return b
}

// One accepted finding accepts one finding.
//
// Under fingerprint v2 the digest is sha256(rule_id || path || message), and
// FindingSet.Add passes the Message — so a rule whose message is a static
// description produces ONE fingerprint for every occurrence in a file. Four
// workflow steps with continue-on-error are four real findings and one digest.
//
// A fingerprint-only lookup accepted all four on the strength of one entry, and
// accepted the fifth somebody added later: born baselined, and `nox scan`
// reported "0 findings (3 suppressed)" for a file whose problems had grown.
func TestOneEntryAcceptsOneFinding(t *testing.T) {
	b := loaded(entry("fp1"))
	m := b.NewMatcher()

	first := finding("fp1", 9)
	if m.Match(&first) == nil {
		t.Fatal("the accepted finding was not matched")
	}
	second := finding("fp1", 12)
	if e := m.Match(&second); e != nil {
		t.Errorf("a second, distinct finding at line 12 consumed entry %+v. Nobody accepted "+
			"it, and under the old lookup nobody would ever have seen it either.", e)
	}
	third := finding("fp1", 15)
	if m.Match(&third) != nil {
		t.Error("a third finding was suppressed by a baseline holding one entry")
	}
}

// N entries accept N findings, which is what makes `nox baseline write` on a
// file with four occurrences mean what it says.
func TestEntriesAcceptExactlyTheirCount(t *testing.T) {
	b := loaded(entry("fp1"), entry("fp1"), entry("fp1"))
	m := b.NewMatcher()

	var accepted int
	for line := 1; line <= 5; line++ {
		f := finding("fp1", line)
		if m.Match(&f) != nil {
			accepted++
		}
	}
	if accepted != 3 {
		t.Errorf("three entries accepted %d findings, want exactly 3", accepted)
	}
}

// The property v2 exists for, which the fix must not cost: a baselined finding
// that moves up or down its file is still baselined. That is the entire reason
// the line was dropped from the digest, and a fix that reintroduced position
// would have traded one silent failure for a noisy one.
func TestAMovedFindingIsStillAccepted(t *testing.T) {
	b := loaded(entry("fp1"))

	atLine9 := finding("fp1", 9)
	if b.NewMatcher().Match(&atLine9) == nil {
		t.Fatal("the finding was not matched at its original line")
	}
	// Same finding, four lines further down after a comment was added above.
	atLine13 := finding("fp1", 13)
	if b.NewMatcher().Match(&atLine13) == nil {
		t.Error("a baselined finding stopped matching after the code moved; the v2 " +
			"fingerprint is line-independent precisely so this cannot happen")
	}
}

// Each scan gets its own matcher, so consumption never leaks between runs.
func TestMatchersAreIndependent(t *testing.T) {
	b := loaded(entry("fp1"))
	for i := 0; i < 3; i++ {
		f := finding("fp1", 9)
		if b.NewMatcher().Match(&f) == nil {
			t.Fatalf("run %d: the entry was consumed by an earlier matcher", i+1)
		}
	}
}

// An expired entry accepts nothing, and does not occupy a slot that would
// otherwise let a live entry match.
func TestExpiredEntriesAcceptNothing(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	expired := entry("fp1")
	expired.ExpiresAt = &past

	b := loaded(expired)
	f := finding("fp1", 9)
	if e := b.NewMatcher().Match(&f); e != nil {
		t.Errorf("an expired entry accepted a finding: %+v", e)
	}

	// One expired and one live: the live one still works.
	b2 := loaded(expired, entry("fp1"))
	f2 := finding("fp1", 9)
	if b2.NewMatcher().Match(&f2) == nil {
		t.Error("a live entry stopped matching because an expired one shared its fingerprint")
	}
}

// The alias fallback survives counting. A finding that inherited a retired rule
// ID is looked up under the fingerprint that rule would have produced —
// otherwise retiring a duplicate rule ID un-baselines every finding accepted
// under it.
func TestAliasFingerprintsStillMatch(t *testing.T) {
	b := loaded(entry("retired-fp"))
	f := finding("current-fp", 9)
	f.AliasFingerprints = []string{"retired-fp"}

	m := b.NewMatcher()
	if m.Match(&f) == nil {
		t.Fatal("a finding carrying a retired rule's fingerprint was not matched")
	}
	// And the alias entry is consumed, not reusable.
	g := finding("current-fp", 12)
	g.AliasFingerprints = []string{"retired-fp"}
	if m.Match(&g) != nil {
		t.Error("the alias entry accepted a second finding")
	}
}

// A nil baseline suppresses nothing rather than panicking.
func TestNilBaselineMatcherIsUsable(t *testing.T) {
	var b *Baseline
	f := finding("fp1", 9)
	if b.NewMatcher().Match(&f) != nil {
		t.Error("a nil baseline accepted a finding")
	}
}

// Prune counts too. Four entries against two live findings leaves two spares,
// and a spare is exactly what absorbs the next occurrence without anyone
// accepting it.
func TestPruneRemovesSpareEntries(t *testing.T) {
	b := loaded(entry("fp1"), entry("fp1"), entry("fp1"), entry("fp1"))
	removed := b.Prune([]findings.Finding{finding("fp1", 9), finding("fp1", 12)})
	if removed != 2 {
		t.Errorf("Prune removed %d entries, want 2", removed)
	}
	if len(b.Entries) != 2 {
		t.Errorf("baseline kept %d entries, want 2", len(b.Entries))
	}
}
