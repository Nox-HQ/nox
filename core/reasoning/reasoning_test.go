package reasoning_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/reasoning"
)

func candidate(rule string, line int) evidence.Subject {
	return reasoning.Candidate(rule, "app/handler.go", line, 9)
}

// TestNilStoreIsUsable is the property that lets refiners call Record
// unconditionally. If a nil store panicked, every call site would need a guard,
// and a guard written the wrong way at one site is how a refiner silently stops
// recording — the exact failure this package exists to prevent, reintroduced in
// the package that prevents it.
func TestNilStoreIsUsable(t *testing.T) {
	var s *reasoning.Store
	s.Record(evidence.Claim{Kind: evidence.KindStatic, Subject: candidate("SEC-001", 1)})
	s.Refute(candidate("SEC-001", 1), evidence.KindStatic, "nox-scan", "secrets", "why")

	if s.Len() != 0 {
		t.Error("a nil store retained claims")
	}
	if got := s.About(candidate("SEC-001", 1)); len(got.Claims) != 0 {
		t.Error("a nil store returned claims")
	}
	if s.Subjects() != nil {
		t.Error("a nil store returned subjects")
	}
	if r, d := s.Stats(); r != 0 || d != 0 {
		t.Errorf("nil store stats = %d/%d, want 0/0", r, d)
	}
}

// TestClaimsWithoutASubjectAreCountedNotKept pins the one case where dropping is
// right and silence is not: a claim filed against an unusable subject can never
// be retrieved, so keeping it would grow the store without adding anything
// readable — but a producer doing that looks, from every other angle, exactly
// like one that is working. The count is how that becomes visible.
func TestClaimsWithoutASubjectAreCountedNotKept(t *testing.T) {
	s := reasoning.New()
	s.Record(evidence.Claim{Kind: evidence.KindStatic, Statement: "no subject"})
	s.Record(evidence.Claim{Kind: evidence.KindStatic, Subject: evidence.Subject{Kind: evidence.SubjectCandidate}})

	if s.Len() != 0 {
		t.Errorf("store kept %d subject(s) from unusable claims", s.Len())
	}
	recorded, dropped := s.Stats()
	if recorded != 0 {
		t.Errorf("recorded = %d, want 0", recorded)
	}
	if dropped != 2 {
		t.Errorf("droppedWithoutSubject = %d, want 2; a producer filing unretrievable "+
			"claims must be countable", dropped)
	}
}

// TestRefuteAlwaysRefutes guards the deliberate absence of a polarity
// parameter. A helper that could record either direction would eventually
// record the wrong one at a call site whose author was thinking about dropping
// a finding rather than about polarity.
func TestRefuteAlwaysRefutes(t *testing.T) {
	s := reasoning.New()
	subject := candidate("SEC-240", 41)
	s.Refute(subject, evidence.KindStatic, "nox-scan", "secrets", "matched inside a comment")

	l := s.About(subject)
	if l.Len() != 1 {
		t.Fatalf("ledger holds %d claims, want 1", l.Len())
	}
	c := l.Claims[0]
	if !c.Refutes() {
		t.Errorf("Refute recorded a %s claim", c.Polarity.Effective())
	}
	if c.Provenance.Source != "nox-scan" || c.Provenance.Tool != "secrets" {
		t.Errorf("provenance = %+v, want source nox-scan tool secrets", c.Provenance)
	}
	if got := l.ConfidenceAbout(subject); got != evidence.ConfidenceLow {
		t.Errorf("a refuted-only candidate scored %s, want LOW", got)
	}
}

// TestTwoRefinersShareOneSubject is why Candidate builds the ID rather than
// each call site. Two refiners refuting the same match must land in one ledger;
// if they disagreed on the format they would produce two ledgers of one claim
// each and the relationship between them would be invisible.
func TestTwoRefinersShareOneSubject(t *testing.T) {
	s := reasoning.New()
	subject := reasoning.Candidate("SEC-162", "web/page.html", 3, 12)
	s.Refute(subject, evidence.KindStatic, "nox-scan", "secrets", "inside a data: URI payload")
	s.Refute(reasoning.Candidate("SEC-162", "web/page.html", 3, 12), evidence.KindStatic,
		"nox-scan", "secrets", "value is a documentation placeholder")

	if s.Len() != 1 {
		t.Errorf("two refiners on one match produced %d subjects, want 1", s.Len())
	}
	sub := s.About(subject)
	if got := sub.Len(); got != 2 {
		t.Errorf("subject holds %d claims, want 2", got)
	}
}

// TestSubjectsAreSortedForDeterminism. Go randomises map iteration, and a scan
// artifact that reorders between identical runs is not a reproducible one.
func TestSubjectsAreSortedForDeterminism(t *testing.T) {
	var want []evidence.Subject
	for range 20 {
		s := reasoning.New()
		for i := 20; i > 0; i-- {
			s.Refute(candidate(fmt.Sprintf("SEC-%03d", i), i), evidence.KindStatic,
				"nox-scan", "secrets", "reason")
		}
		got := s.Subjects()
		if want == nil {
			want = got
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("subject order differs between runs at %d: %s vs %s", i, got[i], want[i])
			}
		}
	}
}

// TestConcurrentRecording exercises the claim the package makes about itself:
// analyzers run in parallel over artifacts, so the store is written from many
// goroutines. Run with -race.
func TestConcurrentRecording(t *testing.T) {
	s := reasoning.New()
	const workers, each = 8, 50

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				s.Refute(candidate(fmt.Sprintf("SEC-%03d", w), i), evidence.KindStatic,
					"nox-scan", "secrets", "reason")
				s.About(candidate("SEC-000", 0))
				s.Len()
			}
		}()
	}
	wg.Wait()

	if got := s.Len(); got != workers*each {
		t.Errorf("store holds %d subjects, want %d", got, workers*each)
	}
	if recorded, dropped := s.Stats(); recorded != workers*each || dropped != 0 {
		t.Errorf("stats = %d/%d, want %d/0", recorded, dropped, workers*each)
	}
}

// TestAboutReturnsACopy. A caller mutating what it reads would corrupt the
// store for everyone else reading the same subject.
func TestAboutReturnsACopy(t *testing.T) {
	s := reasoning.New()
	subject := candidate("SEC-001", 7)
	s.Refute(subject, evidence.KindStatic, "nox-scan", "secrets", "original")

	got := s.About(subject)
	got.Claims[0].Statement = "tampered"
	got.Add(evidence.Claim{Kind: evidence.KindHeuristic, Subject: subject})

	fresh := s.About(subject)
	if fresh.Len() != 1 {
		t.Errorf("store holds %d claims after a caller mutated its copy, want 1", fresh.Len())
	}
	if fresh.Claims[0].Statement != "original" {
		t.Errorf("stored statement = %q, want %q", fresh.Claims[0].Statement, "original")
	}
}
