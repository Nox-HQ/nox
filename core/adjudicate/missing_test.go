package adjudicate_test

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
	"github.com/nox-hq/nox/core/capability"
)

func subj() evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectCandidate, ID: "SEC-003@a.go:1"}
}

// TestTheCheapestOpenQuestionComesFirst is Milestone L's point.
//
// A verdict that stops somewhere is not a dead end; it is a question with an
// unknown, and naming the unknown turns a report into a next step. The ordering
// is the useful part: reading a file is cheaper than resolving symbols, which
// is cheaper than building a call graph, which is far cheaper than executing
// anything. Not every hypothesis should travel to the bottom of that ladder,
// and the ones that do should arrive having survived the cheap questions.
func TestTheCheapestOpenQuestionComesFirst(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)

	gaps := adjudicate.MissingEvidence(cov, reg, subj())
	if len(gaps) == 0 {
		t.Fatal("a subject nothing concluded about has no open questions")
	}
	for i := 1; i < len(gaps); i++ {
		if gaps[i].Cost < gaps[i-1].Cost {
			t.Errorf("gap %d (%s, cost %d) is cheaper than the one before it (%s, cost %d)",
				i, gaps[i].Capability, gaps[i].Cost, gaps[i-1].Capability, gaps[i-1].Cost)
		}
	}

	// Answering one removes it, whichever way it went. A question that was put
	// and came back negative is answered, not open.
	cov.Record(subj(), capability.LexicalContext, capability.Positive)
	cov.Record(subj(), capability.Taint, capability.Negative)
	after := adjudicate.MissingEvidence(cov, reg, subj())
	for _, g := range after {
		if g.Capability == capability.LexicalContext || g.Capability == capability.Taint {
			t.Errorf("%s was answered and is still reported as an open question", g.Capability)
		}
	}
	if len(after) != len(gaps)-2 {
		t.Errorf("answering two questions closed %d gaps", len(gaps)-len(after))
	}
}

// TestAnInconclusiveAnswerLeavesTheQuestionOpen. "The analysis ran and could
// not tell" is not an answer, and treating it as one is how a scan reports a
// question as settled because somebody asked it once.
func TestAnInconclusiveAnswerLeavesTheQuestionOpen(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)
	cov.Record(subj(), capability.Taint, capability.Unknown)
	cov.Record(subj(), capability.SymbolResolution, capability.TimedOut)

	var sawTaint, sawSymbol bool
	for _, g := range adjudicate.MissingEvidence(cov, reg, subj()) {
		switch g.Capability {
		case capability.Taint:
			sawTaint = true
		case capability.SymbolResolution:
			sawSymbol = true
		}
	}
	if !sawTaint {
		t.Error("a capability that ran and could not determine anything is reported " +
			"as answered")
	}
	if !sawSymbol {
		t.Error("a capability that timed out is reported as answered")
	}
}

// TestTheRecommendationIsSomethingTheReaderCanDo. A gap nothing on this
// installation can fill is real and belongs in the list — it is why the verdict
// stops where it does — but recommending it would send a reader to do something
// they cannot.
func TestTheRecommendationIsSomethingTheReaderCanDo(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)

	gaps := adjudicate.MissingEvidence(cov, reg, subj())
	var unavailable int
	for _, g := range gaps {
		if !g.Available {
			unavailable++
		}
	}
	if unavailable == 0 {
		t.Fatal("every capability is available on this installation, so the " +
			"distinction this test is about cannot be exercised")
	}

	next, ok := adjudicate.CheapestAvailable(gaps)
	if !ok {
		t.Fatal("no open question can be answered on an installation that provides " +
			"lexical context, taint and symbol resolution")
	}
	if !next.Available {
		t.Errorf("recommended %s, which nothing here provides", next.Capability)
	}
	for _, g := range gaps {
		if g.Available && g.Cost < next.Cost {
			t.Errorf("recommended %s (cost %d) when %s (cost %d) is available and cheaper",
				next.Capability, next.Cost, g.Capability, g.Cost)
		}
	}
}

// TestGapsAreNamedAsQuestions. "call_graph: not evaluated" tells a reader what
// is missing; "is there a call path to it?" tells them what they would learn.
func TestGapsAreNamedAsQuestions(t *testing.T) {
	reg := capability.DefaultRegistry()
	for _, g := range adjudicate.MissingEvidence(capability.NewCoverage(reg), reg, subj()) {
		if g.Question == "" {
			t.Errorf("%s is an open question with no question", g.Capability)
		}
	}
}
