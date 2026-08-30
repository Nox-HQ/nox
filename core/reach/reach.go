// Package reach is the vocabulary for reachability propositions and the scope
// each one was established under.
//
// It exists because "reachable" is not one question. The chain from an advisory
// to an exploit passes through several propositions, and evidence for an
// earlier one must never establish a later one:
//
//	package in closure → symbol referenced → a call path exists →
//	a path from an attacker-controlled entry point exists →
//	attacker-controlled data reaches the condition → a runtime path was observed
//
// That invariant was already violated when this package was written. The deps
// analyzer establishes that an advisory's affected import is in the build's
// linked package set — `symbol_referenced` — and recorded it as
// `meta["reachable"]`, which the capability matrix then read as the
// `reachability` capability. A project asking "was reachability answered for my
// code?" was told yes on the strength of a weaker question, and the same
// boolean set the finding's severity.
//
// # The asymmetry, which is the point of the package
//
// Reachable is existential: one witnessed path settles it. Unreachable is
// universal: it claims no path exists, which is only true within some scope,
// and is false the moment the analysis could not see everything.
//
// So the two are not symmetric constructors over a boolean. Established needs a
// witness. NotEstablished needs a scope with no limitations, and refuses to
// build otherwise — an analysis that admits it could not resolve a dispatch
// cannot conclude that nothing reaches the sink. That is "UNSAT on path P ≠ all
// paths impossible", enforced where the claim is constructed rather than
// checked afterwards, because a value that briefly exists in the wrong state is
// a value something can read.
package reach

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
)

// Level is one proposition in the reachability chain.
type Level string

// The chain, weakest first. Each is a strictly stronger claim than the one
// before it, and evidence for one establishes only that one.
const (
	// PackageInClosure — the package is in the dependency closure. It says
	// nothing about whether any code in it is referenced.
	PackageInClosure Level = "package_in_closure"
	// SymbolReferenced — the affected symbol or import is referenced by the
	// build. This is as far as a linker-level answer goes.
	SymbolReferenced Level = "symbol_referenced"
	// CallPathExists — a call path reaches the symbol from somewhere. Needs a
	// call graph.
	CallPathExists Level = "call_path_exists"
	// AttackerEntryPathExists — a call path reaches it from an entry point an
	// attacker can reach. Needs an entry-point set.
	AttackerEntryPathExists Level = "attacker_entry_path_exists"
	// AttackerControlledFlowExists — attacker-controlled data reaches the
	// vulnerable condition. Needs dataflow, not just a call graph.
	AttackerControlledFlowExists Level = "attacker_controlled_flow_exists"
	// RuntimePathObserved — the path was observed executing. Only an active
	// run can establish this, never a scan.
	RuntimePathObserved Level = "runtime_path_observed"
)

// Chain returns the levels in order, weakest first.
func Chain() []Level {
	return []Level{
		PackageInClosure, SymbolReferenced, CallPathExists,
		AttackerEntryPathExists, AttackerControlledFlowExists, RuntimePathObserved,
	}
}

// Above reports whether l is a strictly stronger proposition than other.
func (l Level) Above(other Level) bool {
	return l.rank() > other.rank()
}

func (l Level) rank() int {
	for i, c := range Chain() {
		if c == l {
			return i
		}
	}
	return -1
}

// Valid reports whether l is a defined level.
func (l Level) Valid() bool { return l.rank() >= 0 }

// Limitation is a named reason an analysis could not be complete.
//
// This is Milestone C folded in, and it belongs here rather than in a separate
// model: scope and incompleteness are one question — what did this analysis
// cover, and what defeated it — and splitting them means touching every
// analysis result twice. A capability state of "unknown" collapses every entry
// below into one word, which tells an operator nothing they can act on.
type Limitation string

// The reasons an analysis stops being able to speak for a whole program.
const (
	UnresolvedDispatch   Limitation = "unresolved_dispatch"
	Reflection           Limitation = "reflection"
	ForeignFunctions     Limitation = "ffi"
	DynamicLoading       Limitation = "dynamic_loading"
	BoundedLoops         Limitation = "bounded_loops"
	UnsupportedLanguage  Limitation = "unsupported_language"
	UnsupportedFramework Limitation = "unsupported_framework"
	SolverIncomplete     Limitation = "solver_incomplete"
	BudgetExhausted      Limitation = "budget_exhausted"
	NoEntryPointSet      Limitation = "no_entry_point_set"
)

// Describe returns the limitation in words an operator can act on.
func (l Limitation) Describe() string {
	switch l {
	case UnresolvedDispatch:
		return "a call target could not be resolved, so some paths were not followed"
	case Reflection:
		return "reflection was used, and the targets are not visible statically"
	case ForeignFunctions:
		return "control left the language through a foreign function"
	case DynamicLoading:
		return "code is loaded at runtime and was not available to analyse"
	case BoundedLoops:
		return "loops were unrolled to a bound rather than analysed to a fixpoint"
	case UnsupportedLanguage:
		return "this language is not analysed at this depth"
	case UnsupportedFramework:
		return "a framework's control flow is not modelled"
	case SolverIncomplete:
		return "the solver returned no answer within its limits"
	case BudgetExhausted:
		return "the analysis stopped on a budget rather than on a conclusion"
	case NoEntryPointSet:
		return "no entry points were identified, so nothing could be traced from one"
	default:
		return string(l)
	}
}

// Scope is what an analysis actually covered, and what it could not.
//
// A reachability result without this is unusable in the direction that matters.
// "Not reachable" is a claim about everything the analysis did not find, so it
// is only as good as the search behind it, and a reader who cannot see the
// search cannot weigh the claim.
type Scope struct {
	// Analysis names what produced the result — "go list -deps", "taint
	// engine" — so a reader can judge it.
	Analysis string `json:"analysis"`
	// Capability is the analysis capability this result speaks for. It must
	// match the LEVEL being claimed: linker evidence speaks for
	// SymbolReferenced, not for Reachability.
	Capability capability.AnalysisCapability `json:"capability"`
	// EntryPoints is the set considered. Empty means none were, which makes
	// any claim above CallPathExists impossible rather than merely weak.
	EntryPoints []string `json:"entry_points,omitempty"`
	// BuildID identifies the build or configuration the result is about. A
	// reachability answer is about one build; another build links differently.
	BuildID string `json:"build_id,omitempty"`
	// Limitations are the reasons this analysis could not be exhaustive. A
	// scope carrying any of them cannot support a universal claim.
	Limitations []Limitation `json:"limitations,omitempty"`
}

// Complete reports whether the analysis could see everything it needed to.
// Only a complete scope can support "no path exists".
func (s Scope) Complete() bool { return len(s.Limitations) == 0 }

// Describe states what was searched and what defeated it.
func (s Scope) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", s.Analysis)
	if len(s.EntryPoints) > 0 {
		fmt.Fprintf(&b, ", from %d entry point(s)", len(s.EntryPoints))
	}
	if s.BuildID != "" {
		fmt.Fprintf(&b, ", build %s", s.BuildID)
	}
	if len(s.Limitations) == 0 {
		return b.String()
	}
	reasons := make([]string, 0, len(s.Limitations))
	for _, l := range s.Limitations {
		reasons = append(reasons, l.Describe())
	}
	sort.Strings(reasons)
	fmt.Fprintf(&b, "; incomplete because %s", strings.Join(reasons, "; and "))
	return b.String()
}

// Outcome is what a result concluded about its level.
type Outcome string

const (
	// Established — the proposition holds. Existential: a witness settles it.
	Established Outcome = "established"
	// Refuted — the proposition does not hold, within a complete scope.
	// Universal, and only constructible from a scope with no limitations.
	Refuted Outcome = "refuted"
	// Undetermined — the analysis could not tell. This is the honest default
	// and the only outcome an incomplete scope can reach.
	Undetermined Outcome = "undetermined"
)

// Result is one reachability proposition, its outcome, and the scope it was
// decided under.
type Result struct {
	Subject evidence.Subject `json:"subject"`
	Level   Level            `json:"level"`
	Outcome Outcome          `json:"outcome"`
	Scope   Scope            `json:"scope"`
	// Witness is the path that establishes an existential claim. Required for
	// Established: a claim that something is reachable with nothing to point at
	// is an assertion, not evidence.
	Witness []string `json:"witness,omitempty"`
	// Because states, in words, why the outcome is what it is.
	Because string `json:"because"`
}

// Establish records that a level holds, evidenced by a witness path.
//
// Existential, so one path is enough and the scope's limitations do not matter:
// an analysis that missed some paths can still have found this one.
func Establish(subject evidence.Subject, level Level, scope Scope, witness []string) (Result, bool) {
	if !level.Valid() || len(witness) == 0 {
		// A reachability claim with nothing to point at is an assertion.
		return Result{}, false
	}
	return Result{
		Subject: subject, Level: level, Outcome: Established, Scope: scope,
		Witness: append([]string(nil), witness...),
		Because: fmt.Sprintf("a path was found (%s)", scope.Describe()),
	}, true
}

// Refute records that a level does NOT hold, and refuses unless the scope
// could see everything.
//
// This is the asymmetry, and it is enforced here rather than checked later
// because a Result in the wrong state is a value something can read. An
// analysis that could not resolve a dispatch has not established that nothing
// reaches the sink; it has established that it did not find one, which is
// Undetermined and says so.
//
// The second return is false when the scope is incomplete. Callers get an
// Undetermined result carrying the same limitations, so refusing costs them
// nothing and silently downgrading is not possible.
func Refute(subject evidence.Subject, level Level, scope Scope) (Result, bool) {
	if !level.Valid() {
		return Result{}, false
	}
	if !scope.Complete() {
		return Undeterminable(subject, level, scope), false
	}
	return Result{
		Subject: subject, Level: level, Outcome: Refuted, Scope: scope,
		Because: fmt.Sprintf("an exhaustive search found no path (%s)", scope.Describe()),
	}, true
}

// Undeterminable records that the analysis could not tell, and why.
func Undeterminable(subject evidence.Subject, level Level, scope Scope) Result {
	return Result{
		Subject: subject, Level: level, Outcome: Undetermined, Scope: scope,
		Because: fmt.Sprintf("could not be determined (%s)", scope.Describe()),
	}
}

// Describe is the sentence a person reads. It never asserts safety: a refuted
// level is refuted within a scope, and the scope is named.
func (r Result) Describe() string {
	switch r.Outcome {
	case Established:
		return fmt.Sprintf("%s: yes — %s", r.Level, r.Because)
	case Refuted:
		return fmt.Sprintf("%s: no, within the scope searched — %s", r.Level, r.Because)
	default:
		return fmt.Sprintf("%s: unknown, which is not the same as no — %s", r.Level, r.Because)
	}
}
