package capability

import (
	"sort"
	"sync"

	"github.com/nox-hq/nox-core/evidence"
)

// Coverage records what each capability concluded about each subject.
//
// It stores only what actually happened. The default state is DERIVED from the
// registry rather than written down: a capability something provides but which
// said nothing about a subject is NotEvaluated, and one nothing provides at all
// is Unsupported. That is not only a memory decision — though it is that too,
// since a scan reaching six million findings cannot afford nine states written
// per finding (docs/benchmarks/2026-Q3/ledger-budget.md) — it is also the
// honest one. Pre-seeding every pair with NotEvaluated would make the absence
// of an answer look like a recorded observation.
//
// A nil *Coverage is usable, records nothing, and answers every query from the
// registry alone. That keeps recording sites unconditional, the same property
// that makes reasoning.Store safe to call everywhere.
//
// Safe for concurrent use.
type Coverage struct {
	mu       sync.Mutex
	registry *Registry
	states   map[key]State
}

type key struct {
	subject evidence.Subject
	ac      AnalysisCapability
}

// NewCoverage returns a Coverage that resolves defaults against r.
func NewCoverage(r *Registry) *Coverage {
	return &Coverage{registry: r, states: make(map[key]State)}
}

// Record notes that cap reached state about subject.
//
// Recording NotEvaluated is a no-op: it is the default, and storing it would
// grow the map without changing any answer. An invalid capability or state is
// dropped, because a producer that cannot name what it did has not reported a
// result — and storing it would make the matrix look more covered than it is.
func (c *Coverage) Record(subject evidence.Subject, ac AnalysisCapability, state State) {
	if c == nil || !ac.Valid() || !state.Valid() || state == NotEvaluated {
		return
	}
	if !subject.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.states == nil {
		c.states = make(map[key]State)
	}
	c.states[key{subject, ac}] = state
}

// State returns what cap concluded about subject.
//
// The order of the fallbacks is the design. A recorded state wins. Otherwise a
// capability nothing provides is Unsupported — a limit nox can state plainly.
// Only a capability that IS provided and still said nothing is NotEvaluated: a
// gap rather than a limit, and the one an operator can actually act on.
func (c *Coverage) State(subject evidence.Subject, ac AnalysisCapability) State {
	if !ac.Valid() {
		return Unsupported
	}
	if c != nil {
		c.mu.Lock()
		s, ok := c.states[key{subject, ac}]
		c.mu.Unlock()
		if ok {
			return s
		}
	}
	var reg *Registry
	if c != nil {
		reg = c.registry
	}
	if !reg.Provided(ac) {
		return Unsupported
	}
	return NotEvaluated
}

// Subjects returns every subject something was recorded about, sorted.
func (c *Coverage) Subjects() []evidence.Subject {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[evidence.Subject]bool, len(c.states))
	for k := range c.states {
		seen[k.subject] = true
	}
	out := make([]evidence.Subject, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Len returns how many (subject, capability) results were recorded.
func (c *Coverage) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.states)
}

// Gap describes one capability that did not reach a conclusion about a subject,
// and why.
type Gap struct {
	Capability AnalysisCapability `json:"capability"`
	State      State              `json:"state"`
	Reason     string             `json:"reason"`
}

// Gaps returns every capability that did not conclude about subject, cheapest
// first.
//
// This is the answer to "what does nox not know about this finding?", and it is
// the thing that has to be reported rather than implied. A finding with
// Reachability in this list has NOT been shown to be reachable — and, far more
// importantly, has not been shown to be unreachable either. Presenting it
// without the gap invites the reader to supply the more comfortable of the two
// readings.
func (c *Coverage) Gaps(subject evidence.Subject) []Gap {
	var out []Gap
	for _, ac := range All() {
		s := c.State(subject, ac)
		if s.Conclusive() {
			continue
		}
		out = append(out, Gap{Capability: ac, State: s, Reason: s.Describe()})
	}
	return out
}

// Summary counts how many results landed in each state across the whole scan.
// Recorded results only — the derived defaults are not counted, because
// counting a default as an observation is the error this type exists to avoid.
func (c *Coverage) Summary() map[State]int {
	out := make(map[State]int)
	if c == nil {
		return out
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.states {
		out[s]++
	}
	return out
}

// Answered reports how many subjects ac actually concluded about in this scan,
// and how many it was asked about and could not determine.
//
// This is the run-level question, as distinct from the installation-level one
// Registry.Provided answers. The two come apart exactly when something fails at
// runtime: `reachability` is provided by every nox build because
// core/analyzers/deps is compiled in, and on a scan whose advisory source was
// unreachable it establishes nothing at all. An operator asking "was
// reachability answered for my code?" is asking this, not that.
//
// Negative counts as answered. It is a real conclusion — "the build links no
// package under crypto/md5" — and the strongest one a static scan can reach.
// What must never count is Unknown and TimedOut: those are the two states that
// mean the question was put and came back empty, and letting them satisfy a
// requirement would rebuild the false all-clear one layer up.
func (c *Coverage) Answered(ac AnalysisCapability) (answered, inconclusive int) {
	if c == nil || !ac.Valid() {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, state := range c.states {
		if k.ac != ac {
			continue
		}
		switch state {
		case Positive, Negative:
			answered++
		case Unknown, TimedOut:
			inconclusive++
		}
	}
	return answered, inconclusive
}
