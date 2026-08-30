// Package applicability answers the question a developer actually asks about a
// dependency vulnerability: does this affect my code?
//
// It is a separate axis from exploitability, and keeping them separate is the
// first decision this package makes.
//
// The roadmap asks for "PREVENTED as a normal scan result" — show the
// vulnerability, and say it is not currently impacting this application.
// Implemented literally that would corrupt the evidence kernel, whose PREVENTED
// means "not exploited under the strategies tested; a defense was observed".
// That state requires EXECUTION. A scan executes nothing and derives POTENTIAL,
// correctly. Reusing PREVENTED for a static unreachability result would claim a
// defense was observed when nothing ran — a false statement at exactly the
// point a reader is deciding whether to act.
//
// So the honest answer is a second axis. A vulnerability can be POTENTIAL on
// the exploitability ladder (nobody tried to exploit it) and NOT IMPACTING on
// this one (the affected code is not in the build). Both are true, neither
// implies the other, and collapsing them loses the distinction that makes the
// second one worth reporting.
package applicability

import (
	"fmt"

	"github.com/nox-hq/nox/core/capability"
)

// Rung is one step in the argument from "this advisory exists" to "an attacker
// can use it against this application".
//
// The ladder is the point. A scanner that reports only the bottom rung floods
// its user; one that claims the top rung it cannot establish misleads them.
// Naming every step lets nox say exactly how far it got, which is a more useful
// and more honest answer than either.
type Rung string

// The rungs, weakest first.
const (
	// Present — the dependency is in the build. Every dependency finding
	// establishes this and nothing more, which is why a scanner that stops here
	// produces a list nobody triages.
	Present Rung = "present"
	// AffectedVersion — and the resolved version falls in the advisory's range.
	AffectedVersion Rung = "affected_version"
	// SymbolUsed — and the specific package the advisory names is linked by
	// this build. Linked is not called: the code is present, not proven to run.
	SymbolUsed Rung = "symbol_used"
	// CallReachable — and a call path reaches it from somewhere that executes.
	CallReachable Rung = "call_reachable"
	// AttackerReachable — and an attacker can cause that path to be taken.
	// Strictly stronger than CallReachable, and separate because conflating
	// them turns "the code runs" into "the code is exploitable".
	AttackerReachable Rung = "attacker_reachable"
)

// ladder is the ordered set. Order is meaning here, not presentation: a rung is
// established only if every rung below it is.
var ladder = []Rung{Present, AffectedVersion, SymbolUsed, CallReachable, AttackerReachable}

// Ladder returns the rungs, weakest first.
func Ladder() []Rung {
	out := make([]Rung, len(ladder))
	copy(out, ladder)
	return out
}

// index returns a rung's position, or -1 if it is not a defined rung.
func (r Rung) index() int {
	for i, v := range ladder {
		if v == r {
			return i
		}
	}
	return -1
}

// Valid reports whether r is a defined rung.
func (r Rung) Valid() bool { return r.index() >= 0 }

// Above reports whether r is a stronger claim than other.
func (r Rung) Above(other Rung) bool {
	ri, oi := r.index(), other.index()
	return ri >= 0 && oi >= 0 && ri > oi
}

// Next returns the rung above r, and whether one exists.
func (r Rung) Next() (Rung, bool) {
	i := r.index()
	if i < 0 || i+1 >= len(ladder) {
		return "", false
	}
	return ladder[i+1], true
}

// Outcome is what the climb concluded.
type Outcome string

// Outcomes.
const (
	// Undetermined — the climb stopped because something could not be
	// established, not because anything was refuted. The default, and by far
	// the most common: nox has no call-graph analysis, so almost every
	// dependency finding stops below CallReachable.
	Undetermined Outcome = "undetermined"
	// NotImpacting — a rung was DETERMINISTICALLY refuted, so the argument
	// cannot continue. This is the only outcome that may justify de-emphasising
	// a finding, and it requires the same evidence Gate B requires: an analysis
	// that ran and established the negative.
	NotImpacting Outcome = "not_impacting"
)

// Verdict is how far the applicability argument got, and why it stopped.
//
// It deliberately carries the reason alongside the result. "Stopped at
// CallReachable" is not actionable; "stopped at CallReachable because no
// call-graph analysis is available on this installation" tells an operator
// what to install. And it keeps the two ways of not advancing distinguishable:
// a refuted rung and an unevaluated one both stop the climb and mean opposite
// things.
type Verdict struct {
	// Reached is the highest rung positively established.
	Reached Rung `json:"reached"`
	// Outcome says whether the climb stopped on a refutation or on an absence.
	Outcome Outcome `json:"outcome"`
	// StoppedAt is the rung that could not be established.
	StoppedAt Rung `json:"stopped_at,omitempty"`
	// Because is the evaluation state of the analysis that would have
	// established StoppedAt — the capability vocabulary, so "unknown",
	// "unsupported" and "not evaluated" stay distinguishable here too.
	Because capability.State `json:"because,omitempty"`
	// Path is the evidence trail, when there is one. It is what keeps a
	// reachability conclusion auditable rather than a boolean a reader has to
	// take on trust.
	Path []string `json:"path,omitempty"`
}

// Describe renders the verdict as the sentence a developer should read.
//
// It never says "safe" and never says "prevented". The strongest thing it will
// say is that a vulnerability does not currently impact this application, with
// the reason attached — and it says that only when something was actually
// established, never merely because nothing was found.
func (v Verdict) Describe() string {
	switch v.Outcome {
	case NotImpacting:
		return fmt.Sprintf("present, but not currently impacting this application: %s",
			refutedAt(v.StoppedAt))
	default:
		if v.StoppedAt == "" {
			return fmt.Sprintf("established as far as %q", v.Reached)
		}
		return fmt.Sprintf("established as far as %q; %s was not established (%s)",
			v.Reached, v.StoppedAt, v.Because.Describe())
	}
}

// refutedAt explains what a refuted rung means in a developer's terms.
func refutedAt(r Rung) string {
	switch r {
	case SymbolUsed:
		return "the affected package is not linked by this build"
	case CallReachable:
		return "no call path reaches the affected code"
	case AttackerReachable:
		return "the affected code is not reachable from attacker-controlled input"
	case AffectedVersion:
		return "the resolved version is outside the advisory's affected range"
	default:
		return "an applicability requirement was established not to hold"
	}
}

// Undeterminable builds a verdict for a climb that stopped on an absence.
//
// The reason is required rather than optional. A verdict that stopped for an
// unrecorded reason is the "reachability unavailable reads as unreachable"
// failure with an extra field, and a caller that had no reason to give
// probably has no business claiming the climb stopped at all.
func Undeterminable(reached, stoppedAt Rung, because capability.State) Verdict {
	return Verdict{Reached: reached, Outcome: Undetermined, StoppedAt: stoppedAt, Because: because}
}

// Refuted builds a verdict for a rung deterministically established not to hold.
//
// capability.Negative is the only state that may produce this, which is Gate B
// expressed where the verdict is constructed rather than checked afterwards:
// an undetermined result cannot be turned into a NotImpacting verdict by a
// caller that would rather it were one.
func Refuted(reached, refutedRung Rung, state capability.State, path []string) Verdict {
	if !state.SuppressesFinding() {
		return Undeterminable(reached, refutedRung, state)
	}
	return Verdict{
		Reached:   reached,
		Outcome:   NotImpacting,
		StoppedAt: refutedRung,
		Because:   state,
		Path:      path,
	}
}
