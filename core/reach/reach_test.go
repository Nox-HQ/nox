package reach_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/reach"
)

func subject() evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectPackage, ID: "golang.org/x/crypto/ssh"}
}

func completeScope() reach.Scope {
	return reach.Scope{
		Analysis: "go list -deps", Capability: capability.SymbolResolution,
		BuildID: "go build closure",
	}
}

// TestUnreachableIsUniversalAndRefusesAnIncompleteScope is the asymmetry, and
// the reason this package exists as constructors rather than a struct.
//
// Reachable is existential: one witnessed path settles it, and an analysis that
// missed other paths can still have found this one. Unreachable is universal:
// it claims no path exists, which is only true within the scope searched and is
// false the moment the analysis could not see everything.
//
// So an analysis that hit unresolved dispatch, reflection, FFI or a budget has
// not established that nothing reaches the sink. It has established that it did
// not find one, which is Undetermined. Enforced at construction because a
// Result in the wrong state is a value something can read.
func TestUnreachableIsUniversalAndRefusesAnIncompleteScope(t *testing.T) {
	for _, lim := range []reach.Limitation{
		reach.UnresolvedDispatch, reach.Reflection, reach.ForeignFunctions,
		reach.DynamicLoading, reach.BoundedLoops, reach.UnsupportedLanguage,
		reach.UnsupportedFramework, reach.SolverIncomplete, reach.BudgetExhausted,
		reach.NoEntryPointSet,
	} {
		scope := completeScope()
		scope.Limitations = []reach.Limitation{lim}

		got, ok := reach.Refute(subject(), reach.CallPathExists, scope)
		if ok {
			t.Errorf("%s: a negative was built from an analysis that admits it could "+
				"not see everything. That is UNSAT on one path read as no path "+
				"existing", lim)
		}
		if got.Outcome != reach.Undetermined {
			t.Errorf("%s: refused refutation produced %q, want undetermined — the "+
				"caller must get the honest answer, not nothing", lim, got.Outcome)
		}
		if !strings.Contains(got.Because, lim.Describe()) {
			t.Errorf("%s: the result does not say why it could not tell: %q", lim, got.Because)
		}
	}

	// A complete scope CAN support the universal claim: `go list -deps`
	// enumerates the whole closure, so "no affected import is linked" is a
	// statement this analysis is entitled to make.
	if _, ok := reach.Refute(subject(), reach.SymbolReferenced, completeScope()); !ok {
		t.Error("an exhaustive analysis could not state a negative, which leaves nox " +
			"unable to ever say a dependency does not apply")
	}
}

// TestReachableNeedsAWitness. The existential claim is cheap to make and must
// still point at something: "reachable" with nothing to show is an assertion,
// and it is the direction that costs a developer their afternoon.
func TestReachableNeedsAWitness(t *testing.T) {
	if _, ok := reach.Establish(subject(), reach.CallPathExists, completeScope(), nil); ok {
		t.Error("a reachability claim was accepted with no path to point at")
	}
	r, ok := reach.Establish(subject(), reach.CallPathExists, completeScope(),
		[]string{"main → handler → ssh.Marshal"})
	if !ok || len(r.Witness) == 0 {
		t.Fatal("a witnessed path did not establish reachability")
	}

	// An incomplete scope does NOT block the existential claim. Finding a path
	// is still finding a path.
	scope := completeScope()
	scope.Limitations = []reach.Limitation{reach.Reflection}
	if _, ok := reach.Establish(subject(), reach.CallPathExists, scope, []string{"p"}); !ok {
		t.Error("an incomplete analysis was blocked from reporting a path it found; " +
			"reachable is existential and one witness settles it")
	}
}

// TestTheChainIsOrdered. Order is meaning: each level is a strictly stronger
// claim, and evidence for one must not establish a later one.
func TestTheChainIsOrdered(t *testing.T) {
	chain := reach.Chain()
	for i := 1; i < len(chain); i++ {
		if !chain[i].Above(chain[i-1]) {
			t.Errorf("%q is not above %q", chain[i], chain[i-1])
		}
	}
	if reach.PackageInClosure.Above(reach.RuntimePathObserved) {
		t.Error("the weakest proposition outranks the strongest")
	}
	if reach.SymbolReferenced.Above(reach.CallPathExists) {
		t.Error("symbol_referenced outranks call_path_exists — the exact confusion " +
			"this vocabulary was written to end, where linker evidence was recorded " +
			"as the reachability capability")
	}
	if (reach.Level("invented")).Valid() {
		t.Error("an undefined level validated")
	}
}

// TestNoOutcomeAssertsSafety. A refuted level is refuted WITHIN A SCOPE, and
// the wording has to carry that or a reader takes it for a clearance.
func TestNoOutcomeAssertsSafety(t *testing.T) {
	scope := completeScope()
	incomplete := completeScope()
	incomplete.Limitations = []reach.Limitation{reach.UnresolvedDispatch}

	refuted, _ := reach.Refute(subject(), reach.SymbolReferenced, scope)
	established, _ := reach.Establish(subject(), reach.SymbolReferenced, scope, []string{"x"})
	undetermined := reach.Undeterminable(subject(), reach.CallPathExists, incomplete)

	banned := []string{"safe", "secure", "no risk", "not vulnerable", "prevented", "clean"}
	for _, r := range []reach.Result{refuted, established, undetermined, {}} {
		got := strings.ToLower(r.Describe())
		for _, w := range banned {
			if strings.Contains(got, w) {
				t.Errorf("%q contains %q", got, w)
			}
		}
	}
	if !strings.Contains(refuted.Describe(), "within the scope searched") {
		t.Errorf("a refutation reads as absolute: %q", refuted.Describe())
	}
	if !strings.Contains(undetermined.Describe(), "not the same as no") {
		t.Errorf("an undetermined result can be read as a negative: %q", undetermined.Describe())
	}
}

// TestAScopeSaysWhatItSearchedAndWhatDefeatedIt is Milestone C folded in. A
// capability state of "unknown" collapses unresolved dispatch, reflection, FFI
// and a budget into one word, which tells an operator nothing they can act on.
func TestAScopeSaysWhatItSearchedAndWhatDefeatedIt(t *testing.T) {
	s := reach.Scope{
		Analysis: "taint engine", Capability: capability.Taint,
		EntryPoints: []string{"http.HandleFunc"}, BuildID: "abc123",
		Limitations: []reach.Limitation{reach.UnresolvedDispatch},
	}
	got := s.Describe()
	for _, want := range []string{"taint engine", "1 entry point", "abc123", "could not be resolved"} {
		if !strings.Contains(got, want) {
			t.Errorf("scope description %q omits %q", got, want)
		}
	}
	if s.Complete() {
		t.Error("a scope with a limitation reported itself complete, which would let " +
			"it support a universal claim")
	}
}
