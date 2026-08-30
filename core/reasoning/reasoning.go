// Package reasoning records why nox believes — or stopped believing — what a
// scan reports.
//
// The scan pipeline is full of refinements that DROP a candidate: a match
// inside an embedded base64 blob, a documentation placeholder, a bare provider
// prefix with no token body, a credential quoted in an HTML placeholder
// attribute, an assignment-shaped rule that matched prose in a comment. Every
// one of them is a refutation, every one of them is correct, and every one of
// them used to be a bare `continue` — the finding and the reason for dropping
// it both discarded in the same statement.
//
// That is survivable while a refinement is a handful of hand-checked cases. It
// stops being survivable once refinement is the architecture, because a
// refiner that drops the wrong thing produces a result indistinguishable from
// one that had nothing to drop. The reasoning has to be recorded to be
// checkable, and it has to be recorded where it happens, because that is the
// only place the reason is known.
//
// # Why the claims live here and not on the Finding
//
// A refuted candidate never becomes a finding, so there is nothing to hang its
// ledger on. And measurement (docs/benchmarks/2026-Q3/ledger-budget.md) settled
// the shape for the ones that DO survive: a three-claim inline ledger projects
// to 6.62 GiB against 3.48 GiB bare on the largest project nox has scanned. So
// evidence is held out-of-band, keyed by subject, and a Store that was never
// switched on holds nothing and costs nothing.
package reasoning

import (
	"fmt"
	"sort"
	"sync"

	"github.com/nox-hq/nox-core/evidence"
)

// Store collects claims about subjects over the course of one scan.
//
// A nil *Store is usable and discards everything. That is what makes recording
// affordable to call unconditionally: a refiner writes one Record line whether
// or not anybody asked for the reasoning, with no branch at the call site and
// no allocation when the answer is nobody did. The alternative — guarding every
// call — is how half the call sites end up guarded the wrong way.
//
// Safe for concurrent use: analyzers run in parallel over artifacts.
type Store struct {
	mu       sync.Mutex
	ledgers  map[evidence.Subject]*evidence.Ledger
	dropped  int
	recorded int
}

// New returns an empty Store that records.
func New() *Store {
	return &Store{ledgers: make(map[evidence.Subject]*evidence.Ledger)}
}

// Record files a claim about its own subject. It is a no-op on a nil Store, and
// on a claim with no subject: an unattributed claim cannot be retrieved, so
// keeping it would grow the store without adding anything readable.
func (s *Store) Record(c evidence.Claim) {
	if s == nil {
		return
	}
	if !c.Subject.Valid() {
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledgers == nil {
		s.ledgers = make(map[evidence.Subject]*evidence.Ledger)
	}
	l, ok := s.ledgers[c.Subject]
	if !ok {
		l = &evidence.Ledger{}
		s.ledgers[c.Subject] = l
	}
	l.Add(c)
	s.recorded++
}

// Refute is the shorthand every refiner in the pipeline uses: one line, at the
// point where the reason is known, naming what was refuted and why.
//
// The polarity is not a parameter. A helper that could record either direction
// would eventually record the wrong one at a call site whose author was
// thinking about dropping a finding rather than about polarity, and a
// supporting claim mislabelled as refuting is precisely the corruption this
// package exists to make impossible.
func (s *Store) Refute(subject evidence.Subject, kind evidence.Kind, source, tool, statement string) {
	s.Record(evidence.Claim{
		Kind:       kind,
		Statement:  statement,
		Polarity:   evidence.PolarityRefutes,
		Subject:    subject,
		Provenance: evidence.Provenance{Source: source, Tool: tool},
	})
}

// About returns the ledger for one subject. The zero Ledger is returned for a
// subject nothing was recorded about, and for a nil Store.
func (s *Store) About(subject evidence.Subject) evidence.Ledger {
	if s == nil {
		return evidence.Ledger{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.ledgers[subject]
	if !ok {
		return evidence.Ledger{}
	}
	out := evidence.Ledger{Claims: make([]evidence.Claim, len(l.Claims))}
	copy(out.Claims, l.Claims)
	return out
}

// Subjects returns every subject the store holds claims about, sorted for
// determinism. Iteration order over a Go map is randomised, and a scan artifact
// whose contents reorder between identical runs is not a reproducible one.
func (s *Store) Subjects() []evidence.Subject {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]evidence.Subject, 0, len(s.ledgers))
	for subject := range s.ledgers {
		out = append(out, subject)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Len returns the number of subjects the store holds claims about.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ledgers)
}

// Stats returns the number of claims recorded and the number discarded for
// carrying no usable subject.
//
// The second number is the one worth watching. A producer that files claims
// against an invalid subject records nothing retrievable, which looks from
// every other angle exactly like a producer that is working — the failure this
// whole package exists to stop, reproduced inside the package itself.
func (s *Store) Stats() (recorded, droppedWithoutSubject int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recorded, s.dropped
}

// Candidate names the subject every pattern-matching analyzer makes claims
// about: rule R matched at path:line:col, before anything adjudicated it.
//
// The ID is built here rather than at each call site so that two refiners
// refuting the same match file their claims against the same subject. If they
// disagreed on the format they would produce two ledgers of one claim each,
// and the conflict between them — the thing worth seeing — would be invisible.
func Candidate(ruleID, path string, line, column int) evidence.Subject {
	return evidence.Subject{
		Kind: evidence.SubjectCandidate,
		ID:   fmt.Sprintf("%s@%s:%d:%d", ruleID, path, line, column),
	}
}
