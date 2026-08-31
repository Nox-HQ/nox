package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// A GitHub token trips several overlapping rules; dedup collapses them to the
// canonical owner. That collapse is the largest suppression in this analyzer
// and, until now, the only one that recorded nothing.
const dedupSample = "const token = \"ghp_016C7e42F292c6912E7710c838347Ae178B4a\"\n"

func scanRecording(t *testing.T, name, content string) (*findings.FindingSet, *reasoning.Store) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing sample: %v", err)
	}
	store := reasoning.New()
	a := NewAnalyzer()
	a.RecordReasoningTo(store)
	fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{{Path: name, AbsPath: path}})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return fs, store
}

// The headline: a finding dedup drops leaves a record naming what superseded it.
func TestDedupRecordsWhatItDropped(t *testing.T) {
	fs, store := scanRecording(t, "config.js", dedupSample)
	if len(fs.Findings()) == 0 {
		t.Fatal("no finding survived; the sample is meant to carry a real token")
	}

	var withheld []evidence.Claim
	for _, subject := range store.Subjects() {
		for _, c := range store.About(subject).Claims {
			if c.Polarity == evidence.PolarityUnknown && strings.Contains(c.Statement, "same span") {
				withheld = append(withheld, c)
			}
		}
	}
	if len(withheld) == 0 {
		t.Fatal("dedup dropped findings and recorded nothing; the reason for a " +
			"suppression must survive the suppression")
	}
	for _, c := range withheld {
		if c.Statement == "" {
			t.Error("a withheld claim with an empty statement records nothing")
		}
		if c.Subject.ID == "" || !c.Subject.Valid() {
			t.Errorf("withheld claim filed against an unusable subject: %+v", c.Subject)
		}
	}
}

// The polarity is the load-bearing part. A deduped finding was not refuted --
// the token really is a GitHub token -- so recording it against the candidate
// would make the store assert that true detections of a live credential were
// evidence of nothing being there.
func TestDedupSuppressionIsNotARefutation(t *testing.T) {
	_, store := scanRecording(t, "config.js", dedupSample)

	for _, subject := range store.Subjects() {
		for _, c := range store.About(subject).Claims {
			if !c.Refutes() {
				continue
			}
			if strings.Contains(c.Statement, "same span") || strings.Contains(c.Statement, "canonical rule") {
				t.Errorf("dedup filed a REFUTING claim: %q\n"+
					"a deduped finding is redundant, not false", c.Statement)
			}
		}
	}
}

// The relation is what lets a reader ask how many candidates one secret
// accounted for -- the question reasoning.Relate was added for, naming dedup as
// the case whose knowledge was lost the moment it acted.
func TestDedupRelatesTheDroppedCandidateToItsSurvivor(t *testing.T) {
	fs, store := scanRecording(t, "config.js", dedupSample)

	graph := store.Relations()
	if graph.Len() == 0 {
		t.Fatal("dedup collapsed overlapping candidates and recorded no relation between them")
	}

	survivors := fs.Findings()
	if len(survivors) == 0 {
		t.Fatal("no survivor to relate to")
	}
	surviving := reasoning.Candidate(survivors[0].RuleID, "config.js",
		survivors[0].Location.StartLine, survivors[0].Location.StartColumn)

	related := store.Concerning(surviving, evidence.RelConcerns)
	if len(related) == 0 {
		t.Fatalf("no candidate relates to the surviving finding %s; "+
			"Concerning cannot answer how many candidates this one secret accounted for", surviving)
	}
	for _, r := range related {
		if r == surviving {
			t.Error("a finding was related to itself; that edge is a cycle and says nothing")
		}
	}
}

// Every relation must name a survivor that actually survived. A pass-1 anchor
// can itself be a mis-attributed rule dropped moments later, so naming it would
// point the ledger at a finding the scan never reported.
func TestDedupSurvivorActuallySurvives(t *testing.T) {
	fs, store := scanRecording(t, "config.js", dedupSample)

	kept := make(map[string]bool)
	for _, f := range fs.Findings() {
		kept[reasoning.Candidate(f.RuleID, "config.js",
			f.Location.StartLine, f.Location.StartColumn).String()] = true
	}
	for _, r := range store.Relations().Relations {
		if !kept[r.To.String()] {
			t.Errorf("relation points at %s, which is not among the reported findings", r.To)
		}
	}
}

// This change adds evidence and must change no finding. The suppression
// decisions are untouched; only the record of them is new.
func TestDedupSuppressionDecisionsAreUnchanged(t *testing.T) {
	samples := map[string]string{
		"github token":  dedupSample,
		"aws key pair":  "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\nAWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
		"stripe key":    "const k = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n",
		"no secret":     "const greeting = \"hello world\"\n",
		"two on a line": "a = \"ghp_016C7e42F292c6912E7710c838347Ae178B4a\"; b = \"xoxb-1234-5678-abcdefghijklmnop\"\n",
	}
	for name, content := range samples {
		t.Run(name, func(t *testing.T) {
			// With a store and without one must agree: recording is a side
			// channel, never an input to the decision.
			withStore, _ := scanRecording(t, "s.js", content)

			dir := t.TempDir()
			path := filepath.Join(dir, "s.js")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			plain, err := NewAnalyzer().ScanArtifacts(context.Background(),
				[]discovery.Artifact{{Path: "s.js", AbsPath: path}})
			if err != nil {
				t.Fatal(err)
			}

			a, b := withStore.Findings(), plain.Findings()
			if len(a) != len(b) {
				t.Fatalf("recording changed the finding count: %d with a store, %d without", len(a), len(b))
			}
			for i := range a {
				if a[i].RuleID != b[i].RuleID || a[i].Location.StartLine != b[i].Location.StartLine {
					t.Errorf("finding %d differs: %s@%d vs %s@%d", i,
						a[i].RuleID, a[i].Location.StartLine, b[i].RuleID, b[i].Location.StartLine)
				}
			}
		})
	}
}

// A nil store must discard, like every other recording path in this analyzer.
func TestDedupRecordingToleratesNoStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.js")
	if err := os.WriteFile(path, []byte(dedupSample), 0o600); err != nil {
		t.Fatal(err)
	}
	// NewAnalyzer without RecordReasoningTo leaves the store nil.
	if _, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: "config.js", AbsPath: path}}); err != nil {
		t.Fatalf("scanning without a reasoning store: %v", err)
	}
}
