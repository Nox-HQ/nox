package capability_test

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
)

// TestAnsweredSeparatesAConclusionFromASilence is the Gate B discipline one
// layer up.
//
// Answered feeds a policy gate, so whatever it counts as an answer is what can
// satisfy "my triage depends on this". Unknown and TimedOut mean the question
// was put and came back empty; counting either would let a scan that determined
// nothing satisfy a requirement that something be determined, which is the
// false all-clear this whole model exists to prevent.
//
// Negative is on the other side of that line and belongs there: "the build
// links no package under crypto/md5" is a conclusion, and the strongest one a
// static scan reaches.
func TestAnsweredSeparatesAConclusionFromASilence(t *testing.T) {
	cov := capability.NewCoverage(capability.DefaultRegistry())
	subject := func(id string) evidence.Subject {
		return evidence.Subject{Kind: evidence.SubjectCandidate, ID: id}
	}
	cov.Record(subject("a"), capability.Reachability, capability.Positive)
	cov.Record(subject("b"), capability.Reachability, capability.Negative)
	cov.Record(subject("c"), capability.Reachability, capability.Unknown)
	cov.Record(subject("d"), capability.Reachability, capability.TimedOut)
	cov.Record(subject("e"), capability.Reachability, capability.NotEvaluated)
	cov.Record(subject("f"), capability.Reachability, capability.Unsupported)

	answered, inconclusive := cov.Answered(capability.Reachability)
	if answered != 2 {
		t.Errorf("answered = %d, want 2 (Positive and Negative are both conclusions); "+
			"a silence counted as an answer lets a scan that determined nothing "+
			"satisfy a requirement that something be determined", answered)
	}
	if inconclusive != 2 {
		t.Errorf("inconclusive = %d, want 2 (Unknown and TimedOut)", inconclusive)
	}

	// A capability nothing recorded, and an undefined one, both answer nothing
	// rather than defaulting to something reassuring.
	if a, i := cov.Answered(capability.Taint); a != 0 || i != 0 {
		t.Errorf("an unrecorded capability reported (%d, %d), want (0, 0)", a, i)
	}
	if a, i := cov.Answered("invented"); a != 0 || i != 0 {
		t.Errorf("an undefined capability reported (%d, %d), want (0, 0)", a, i)
	}
	var nilCov *capability.Coverage
	if a, i := nilCov.Answered(capability.Reachability); a != 0 || i != 0 {
		t.Errorf("a nil coverage reported (%d, %d), want (0, 0)", a, i)
	}
}
