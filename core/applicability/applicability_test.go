package applicability_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/capability"
)

// TestOnlyADeterministicNegativeProducesNotImpacting is Gate B, enforced where
// the verdict is CONSTRUCTED rather than checked afterwards.
//
// A caller who would rather an undetermined result were a clean one cannot get
// it: Refuted downgrades to Undetermined for any state that is not a conclusive
// negative. Checking this after the fact would leave a window in which the
// wrong verdict exists and something could read it.
func TestOnlyADeterministicNegativeProducesNotImpacting(t *testing.T) {
	for _, s := range []capability.State{
		capability.NotEvaluated, capability.Unsupported, capability.TimedOut,
		capability.Unknown, capability.Positive, capability.State("from-a-newer-build"),
	} {
		v := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed, s, nil)
		if v.Outcome == applicability.NotImpacting {
			t.Errorf("state %q produced NotImpacting; only a conclusive negative may, "+
				"or a scan reports its own blind spot as an all-clear", s)
		}
	}

	v := applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed,
		capability.Negative, []string{"the build links no package under crypto/md5"})
	if v.Outcome != applicability.NotImpacting {
		t.Errorf("a conclusive negative produced %q, want NotImpacting", v.Outcome)
	}
	if len(v.Path) == 0 {
		t.Error("a NotImpacting verdict carries no evidence path; that is the " +
			"unauditable boolean this model exists to replace")
	}
}

// TestDescribeNeverAssertsSafetyOrPrevention checks the wording a developer
// reads, in both directions the wording could overstate.
//
// The second half matters as much as the first. PREVENTED is the kernel's word
// for "a defense was observed after execution", and a static scan executes
// nothing. Borrowing it here would claim a defense was seen where nothing ran.
func TestDescribeNeverAssertsSafetyOrPrevention(t *testing.T) {
	verdicts := []applicability.Verdict{
		{},
		applicability.Undeterminable(applicability.Present, applicability.SymbolUsed, capability.Unknown),
		applicability.Undeterminable(applicability.SymbolUsed, applicability.CallReachable, capability.Unsupported),
		applicability.Refuted(applicability.AffectedVersion, applicability.SymbolUsed, capability.Negative, nil),
	}
	banned := []string{"safe", "secure", "no risk", "not vulnerable", "prevented", "clean"}
	for i, v := range verdicts {
		got := strings.ToLower(v.Describe())
		if got == "" {
			t.Errorf("verdict %d describes itself as nothing", i)
		}
		for _, w := range banned {
			if strings.Contains(got, w) {
				t.Errorf("verdict %d says %q, which contains %q", i, got, w)
			}
		}
	}
}

// TestUndeterminedSaysWhy. "Stopped at call_reachable" is not actionable;
// "stopped because no call-graph analysis is available" tells an operator what
// to install.
func TestUndeterminedSaysWhy(t *testing.T) {
	v := applicability.Undeterminable(applicability.SymbolUsed,
		applicability.CallReachable, capability.Unsupported)
	got := v.Describe()
	if !strings.Contains(got, "linked by this build") {
		t.Errorf("%q does not say how far the climb got", got)
	}
	if !strings.Contains(got, "whether a call path reaches the affected code") {
		t.Errorf("%q does not say where it stopped", got)
	}
	if !strings.Contains(got, "cannot apply") && !strings.Contains(got, "unsupported") {
		t.Errorf("%q does not say why it stopped", got)
	}
}

// The sentence is a finding's message: it is printed in SARIF, in a pull
// request comment and in the terminal, to someone who has never seen the
// ladder. A rung's identifier (symbol_used) is this package's name for a step,
// not a description of it, and it stays in the finding's metadata, where a
// program reads it.
func TestDescribeUsesNoRungIdentifier(t *testing.T) {
	rungs := applicability.Ladder()
	var verdicts []applicability.Verdict
	for i, reached := range rungs {
		verdicts = append(verdicts, applicability.Verdict{Reached: reached, Outcome: applicability.Undetermined})
		verdicts = append(verdicts, applicability.Established(reached, []string{"main", "f"}))
		for _, stopped := range rungs[i+1:] {
			verdicts = append(verdicts,
				applicability.Undeterminable(reached, stopped, capability.Unsupported),
				applicability.Refuted(reached, stopped, capability.Negative, nil))
		}
	}
	for _, v := range verdicts {
		got := v.Describe()
		for _, r := range rungs {
			if strings.Contains(got, string(r)) && strings.Contains(string(r), "_") {
				t.Errorf("Describe(%+v) = %q, which prints the identifier %q", v, got, r)
			}
		}
		if strings.Contains(got, `"`) {
			t.Errorf("Describe(%+v) = %q quotes an identifier instead of saying what it means", v, got)
		}
	}
}

// Every rung has words for each of the three things said about it. A rung
// added without them would print as its identifier.
func TestEveryRungHasWords(t *testing.T) {
	for _, r := range applicability.Ladder() {
		for name, got := range map[string]string{
			"Holds": r.Holds(), "DoesNotHold": r.DoesNotHold(), "Question": r.Question(),
		} {
			if got == "" || strings.Contains(got, string(r)) && strings.Contains(string(r), "_") {
				t.Errorf("%s.%s() = %q", r, name, got)
			}
		}
		if !strings.HasPrefix(r.Question(), "whether ") {
			t.Errorf("%s.Question() = %q, want a clause starting with whether", r, r.Question())
		}
	}
}

// TestTheLadderIsOrdered. Order is meaning here: a rung is established only if
// every rung below it is, so a mis-ordered ladder would let a weaker claim
// outrank a stronger one.
func TestTheLadderIsOrdered(t *testing.T) {
	rungs := applicability.Ladder()
	for i := 1; i < len(rungs); i++ {
		if !rungs[i].Above(rungs[i-1]) {
			t.Errorf("%q is not above %q", rungs[i], rungs[i-1])
		}
	}
	if applicability.Present.Above(applicability.AttackerReachable) {
		t.Error("the weakest rung outranks the strongest")
	}
	if (applicability.Rung("invented")).Valid() {
		t.Error("an undefined rung validated")
	}
	if _, ok := applicability.AttackerReachable.Next(); ok {
		t.Error("the top rung reports one above it")
	}
	if next, ok := applicability.SymbolUsed.Next(); !ok || next != applicability.CallReachable {
		t.Errorf("SymbolUsed.Next() = %q, %v; want call_reachable, true", next, ok)
	}
}
