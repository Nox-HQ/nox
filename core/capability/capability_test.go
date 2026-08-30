package capability_test

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
)

var subject = evidence.Subject{Kind: evidence.SubjectCandidate, ID: "SEC-003@app/creds.py:1:16"}

// TestOnlyAConclusiveNegativeMaySuppress is Gate B written as a test. Four of
// the six states resemble each other in the output — nothing is reported — and
// exactly one of them is a reason to report nothing.
func TestOnlyAConclusiveNegativeMaySuppress(t *testing.T) {
	suppressing := map[capability.State]bool{capability.Negative: true}
	conclusive := map[capability.State]bool{capability.Negative: true, capability.Positive: true}

	for _, s := range []capability.State{
		capability.NotEvaluated, capability.Unsupported, capability.TimedOut,
		capability.Unknown, capability.Negative, capability.Positive,
		capability.State("from-a-newer-build"),
	} {
		if got := s.SuppressesFinding(); got != suppressing[s] {
			t.Errorf("%q.SuppressesFinding() = %v, want %v — only an analysis that "+
				"RAN and established the condition does not hold may hide a finding",
				s, got, suppressing[s])
		}
		if got := s.Conclusive(); got != conclusive[s] {
			t.Errorf("%q.Conclusive() = %v, want %v", s, got, conclusive[s])
		}
	}
}

// TestDescribeNeverAssertsSafety. These strings reach an operator, and the
// distinction the whole package draws is destroyed if the wording lets four
// non-answers read as clearances.
func TestDescribeNeverAssertsSafety(t *testing.T) {
	banned := []string{"safe", "secure", "clean", "no risk", "not vulnerable"}
	for _, s := range []capability.State{
		capability.NotEvaluated, capability.Unsupported, capability.TimedOut,
		capability.Unknown, capability.Negative, capability.Positive,
		capability.State("unrecognised"),
	} {
		got := s.Describe()
		if got == "" {
			t.Errorf("%q has no description", s)
		}
		for _, w := range banned {
			if contains(got, w) {
				t.Errorf("%q describes itself as %q, which contains %q", s, got, w)
			}
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestUnprovidedIsUnsupportedProvidedButSilentIsAGap is the distinction that
// makes NotEvaluated worth having. Both look like silence; only one is
// actionable.
func TestUnprovidedIsUnsupportedProvidedButSilentIsAGap(t *testing.T) {
	r := capability.NewRegistry()
	r.Register(stubProvider{"stub", []capability.AnalysisCapability{capability.Reachability}})
	cov := capability.NewCoverage(r)

	if got := cov.State(subject, capability.Reachability); got != capability.NotEvaluated {
		t.Errorf("a provided but silent capability = %q, want %q — it is a gap, not a limit",
			got, capability.NotEvaluated)
	}
	if got := cov.State(subject, capability.CallGraph); got != capability.Unsupported {
		t.Errorf("an unprovided capability = %q, want %q", got, capability.Unsupported)
	}

	cov.Record(subject, capability.Reachability, capability.Negative)
	if got := cov.State(subject, capability.Reachability); got != capability.Negative {
		t.Errorf("a recorded state = %q, want %q", got, capability.Negative)
	}
}

// TestNilCoverageAnswersFromTheRegistry pins the property that lets recording
// sites be unconditional, and checks the nil path still gives honest answers
// rather than a convenient default.
func TestNilCoverageAnswersFromTheRegistry(t *testing.T) {
	var cov *capability.Coverage
	cov.Record(subject, capability.Taint, capability.Positive)

	if cov.Len() != 0 {
		t.Error("a nil coverage retained a result")
	}
	if got := cov.State(subject, capability.Taint); got != capability.Unsupported {
		t.Errorf("nil coverage reports %q; with no registry nothing is known to be "+
			"provided, so the honest answer is %q", got, capability.Unsupported)
	}
	for _, g := range cov.Gaps(subject) {
		if g.State.Conclusive() {
			t.Errorf("nil coverage reported a conclusive gap: %+v", g)
		}
	}
}

// TestGapsListEverythingUnconcluded. This is what a finding's "what was not
// evaluated?" answer is built from, and omitting one is how a blind spot stops
// being visible.
func TestGapsListEverythingUnconcluded(t *testing.T) {
	cov := capability.NewCoverage(capability.DefaultRegistry())
	cov.Record(subject, capability.LexicalContext, capability.Positive)
	cov.Record(subject, capability.Taint, capability.Negative)

	gaps := cov.Gaps(subject)
	if want := len(capability.All()) - 2; len(gaps) != want {
		t.Errorf("Gaps returned %d, want %d (every capability that did not conclude)",
			len(gaps), want)
	}
	for _, g := range gaps {
		if g.Capability == capability.LexicalContext || g.Capability == capability.Taint {
			t.Errorf("%q concluded but was reported as a gap", g.Capability)
		}
		if g.Reason == "" {
			t.Errorf("gap %q has no reason", g.Capability)
		}
	}
}

// TestUnknownCapabilitiesAreNeverTreatedAsCoverage. A producer claiming a
// capability nox does not know about has told nox nothing, and recording it
// would make the matrix look more covered than it is.
func TestUnknownCapabilitiesAreNeverTreatedAsCoverage(t *testing.T) {
	r := capability.NewRegistry()
	r.Register(stubProvider{"optimist", []capability.AnalysisCapability{"solves_halting_problem"}})

	if r.Provided("solves_halting_problem") {
		t.Error("an undefined capability was registered as provided")
	}
	cov := capability.NewCoverage(r)
	cov.Record(subject, "solves_halting_problem", capability.Negative)
	if cov.Len() != 0 {
		t.Error("a result for an undefined capability was recorded")
	}
	if got := cov.State(subject, "solves_halting_problem"); got.SuppressesFinding() {
		t.Errorf("an undefined capability reported %q, which may suppress a finding", got)
	}
}

// TestBuiltinsAreHonestAboutWhatIsMissing. The list is hand-written, so this
// pins the claims that would be most damaging to get wrong: nox must not
// declare capabilities a pattern scanner does not have.
func TestBuiltinsAreHonestAboutWhatIsMissing(t *testing.T) {
	r := capability.DefaultRegistry()

	for _, c := range []capability.AnalysisCapability{
		capability.CallGraph, capability.EntryPoint, capability.ConstantEvaluation,
	} {
		if r.Provided(c) {
			t.Errorf("%q is declared as built-in; nox has no such analysis, and "+
				"claiming one turns a limit into a false assurance", c)
		}
	}
	for _, c := range []capability.AnalysisCapability{
		capability.LexicalContext, capability.Taint, capability.Reachability,
	} {
		if !r.Provided(c) {
			t.Errorf("%q is not declared but nox does provide it; an undeclared "+
				"capability reads as Unsupported when it is really available", c)
		}
	}
	if len(r.Missing()) == 0 {
		t.Error("the registry claims nox is missing nothing, which cannot be true " +
			"of a scanner that never executes the code it reads")
	}
}

type stubProvider struct {
	name     string
	provides []capability.AnalysisCapability
}

func (s stubProvider) Name() string                              { return s.name }
func (s stubProvider) Provides() []capability.AnalysisCapability { return s.provides }
