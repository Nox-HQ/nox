package capability

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

func sub(id string) evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectCandidate, ID: id}
}

// THE EXIT CRITERION for milestone 2.2: one scan legitimately holds different
// competence states for different findings.
//
// The run-level matrix cannot express this. It can say constant evaluation ran;
// it cannot say it ran for the Go findings and could not apply to the YAML
// ones. A consumer with only the run-level view has to assume the best case for
// every finding, and the best case is the reading this model exists to
// withhold.
func TestOneScanHoldsDifferentCompetencePerSubject(t *testing.T) {
	reg := DefaultRegistry()
	cov := NewCoverage(reg)

	// A Go finding: lexed, constants evaluated, taint concluded.
	goSubj := sub("SEC-001@main.go:4:9")
	cov.Record(goSubj, LexicalContext, Positive)
	cov.Record(goSubj, ConstantEvaluation, Positive)
	cov.Record(goSubj, Taint, Positive)
	cov.Record(goSubj, SymbolResolution, Positive)

	// A YAML finding: no lexer, no evaluator, nothing else asked.
	yamlSubj := sub("DATA-001@values.yaml:2:1")
	cov.Record(yamlSubj, LexicalContext, Unsupported)
	cov.Record(yamlSubj, ConstantEvaluation, Unsupported)

	profiles, assignment := Profiles(cov, []evidence.Subject{goSubj, yamlSubj})
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles for two genuinely different competence states, want 2", len(profiles))
	}
	if assignment[goSubj] == assignment[yamlSubj] {
		t.Fatalf("both subjects resolved to profile %q; a finding nox lexed and one it could "+
			"not read are being reported as equally well understood", assignment[goSubj])
	}

	byID := map[string]Profile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	// The YAML finding's profile must name lexical_context as unsupported. If
	// it does not, the artifact says nox distinguished code from comments in a
	// file it has no lexer for.
	var found bool
	for _, g := range byID[assignment[yamlSubj]].Gaps {
		if g.Capability == LexicalContext && g.State == Unsupported {
			found = true
		}
	}
	if !found {
		t.Error("the YAML finding's profile does not record lexical_context as unsupported")
	}
	// And the Go finding's must NOT, because it was answered.
	for _, g := range byID[assignment[goSubj]].Gaps {
		if g.Capability == LexicalContext {
			t.Errorf("the Go finding's profile lists lexical_context as %q; it was answered", g.State)
		}
	}
}

// Profile IDs are assigned in sorted signature order, so two runs over the same
// tree number them identically. A scan artifact that renumbers between runs is
// not a reproducible one.
func TestProfileIDsAreDeterministic(t *testing.T) {
	reg := DefaultRegistry()
	build := func() ([]Profile, map[evidence.Subject]string) {
		cov := NewCoverage(reg)
		subjects := []evidence.Subject{}
		for _, spec := range []struct {
			id  string
			cap AnalysisCapability
		}{
			{"z", Taint}, {"a", LexicalContext}, {"m", ConstantEvaluation},
			{"b", Taint}, {"q", LexicalContext},
		} {
			s := sub(spec.id)
			cov.Record(s, spec.cap, Positive)
			subjects = append(subjects, s)
		}
		return Profiles(cov, subjects)
	}

	p1, a1 := build()
	for i := 0; i < 8; i++ {
		p2, a2 := build()
		if len(p1) != len(p2) {
			t.Fatalf("profile count moved between runs: %d then %d", len(p1), len(p2))
		}
		for j := range p1 {
			if p1[j].ID != p2[j].ID || p1[j].Subjects != p2[j].Subjects {
				t.Fatalf("profile %d differs between runs: %+v vs %+v", j, p1[j], p2[j])
			}
		}
		for s, id := range a1 {
			if a2[s] != id {
				t.Fatalf("subject %s moved from %q to %q between runs", s.ID, id, a2[s])
			}
		}
	}
}

// A subject nothing was recorded about still gets a profile — the one where
// nothing concluded. Leaving it out would put the findings nox knows least
// about into the group with no entry at all, which reads as no gaps.
func TestUnrecordedSubjectStillGetsAProfile(t *testing.T) {
	cov := NewCoverage(DefaultRegistry())
	s := sub("SEC-001@x.txt:1:1")

	profiles, assignment := Profiles(cov, []evidence.Subject{s})
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(profiles))
	}
	if assignment[s] == "" {
		t.Fatal("a subject nothing was recorded about got no profile")
	}
	if len(profiles[0].Gaps) != len(All()) {
		t.Errorf("profile has %d gaps, want all %d capabilities: nothing concluded about this "+
			"subject, and a short list would understate that", len(profiles[0].Gaps), len(All()))
	}
}

// A nil Coverage yields nothing. Inventing a full-coverage profile for a scan
// that recorded no competence would be the opposite of true.
func TestNilCoverageInventsNoProfile(t *testing.T) {
	profiles, assignment := Profiles(nil, []evidence.Subject{sub("a")})
	if profiles != nil || assignment != nil {
		t.Errorf("nil coverage produced %d profiles and %d assignments", len(profiles), len(assignment))
	}
}

// A repeated subject is one subject. Counting it twice would make a profile
// look like it covers more of the scan than it does.
func TestRepeatedSubjectsCountOnce(t *testing.T) {
	cov := NewCoverage(DefaultRegistry())
	s := sub("SEC-001@a.go:1:1")
	cov.Record(s, LexicalContext, Positive)

	profiles, _ := Profiles(cov, []evidence.Subject{s, s, s})
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(profiles))
	}
	if profiles[0].Subjects != 1 {
		t.Errorf("Subjects = %d for one subject listed three times, want 1", profiles[0].Subjects)
	}
}
