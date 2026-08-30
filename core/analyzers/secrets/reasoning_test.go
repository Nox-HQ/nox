package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/reasoning"
)

// refutationCase is one drop the secrets analyzer performs, with a sample that
// triggers it and a fragment of the reason it must record.
type refutationCase struct {
	name    string
	file    string
	content string
	// wantReason is a distinctive fragment of the claim's statement. Matching a
	// fragment rather than the whole string keeps the test about WHICH refiner
	// fired, not about its prose.
	wantReason string
}

// refutationCases covers all six drops in ScanArtifacts' refinement loop. It is
// exhaustive on purpose: five refiners recording their reasoning and one
// silently dropping is the same defect as none of them recording, and it is a
// good deal harder to notice.
var refutationCases = []refutationCase{
	{
		name:       "documentation placeholder",
		file:       "config.py",
		content:    "API_KEY = \"your-api-key-here\"\nPASSWORD = \"changeme\"\n",
		wantReason: "documentation placeholder",
	},
	{
		name:       "display-text attribute",
		file:       "form.jsx",
		content:    "export const F = () => <input placeholder=\"-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA7Zx\" />;\n",
		wantReason: "display-text HTML/JSX attribute",
	},
	{
		// .html is LangUnknown to lexctx, so inEmbeddedBlob cannot see it and
		// the raw-bytes data: marker is what catches it. That asymmetry is why
		// both refiners exist.
		name:       "data URI payload",
		file:       "page.html",
		content:    "<img src=\"data:image/png;base64,AKIAIOSFODNN7EXAMPLE\">\n",
		wantReason: "data: URI payload",
	},
	{
		// The same shape in lexable source is caught one refiner earlier.
		name:       "embedded blob in lexable source",
		file:       "icons.py",
		content:    "ICON = \"data:image/png;base64,AKIAIOSFODNN7EXAMPLE\"\n",
		wantReason: "embedded data blob",
	},
	{
		name:       "assignment-shaped rule in a comment",
		file:       "doc.go",
		content:    "package p\n\n// \"bot_token\" pops a password input, \"imap_password\" pops an app-password wizard.\nfunc F() {}\n",
		wantReason: "within a comment region",
	},
}

// isBareProviderPrefix is the sixth drop in the loop and is deliberately absent
// from the table above. No input reached it: a bare `AKIA` or `"glpat-"` is not
// matched by any rule, because provider patterns require a token body, so the
// refiner never sees a candidate to refute. It is wired like the other five and
// will record if it ever fires — but this file does not claim to have proved
// that, because a test asserting a drop that cannot happen proves nothing.
// See the note in TestScan_DataURIPayloadIsNotASecret for the same defect found
// in an existing test.

// scanWithReasoning runs the analyzer over one file and returns the findings it
// kept alongside the store it recorded into.
func scanWithReasoning(t *testing.T, name, content string) (int, *reasoning.Store) {
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
	return len(fs.Findings()), store
}

// TestEveryDropRecordsItsReason is E1: the reasoning behind a suppression must
// survive the suppression.
//
// It is deliberately not satisfied by "a claim was recorded". A store that
// filed an empty statement, or filed against an unusable subject, or recorded a
// SUPPORTING claim for something it dropped, would all pass a shallower check
// while being useless or actively wrong. Each is asserted.
func TestEveryDropRecordsItsReason(t *testing.T) {
	for _, tc := range refutationCases {
		t.Run(tc.name, func(t *testing.T) {
			_, store := scanWithReasoning(t, tc.file, tc.content)

			recorded, droppedWithoutSubject := store.Stats()
			if droppedWithoutSubject != 0 {
				t.Errorf("%d claim(s) filed against an unusable subject; they are "+
					"unretrievable, which looks identical to not recording at all",
					droppedWithoutSubject)
			}
			if recorded == 0 {
				t.Fatalf("the analyzer dropped a candidate and recorded nothing about it")
			}

			var found bool
			for _, subject := range store.Subjects() {
				if subject.Kind != evidence.SubjectCandidate {
					t.Errorf("claim filed against subject kind %q, want %q",
						subject.Kind, evidence.SubjectCandidate)
				}
				ledger := store.About(subject)
				for _, c := range ledger.Claims {
					if !c.Refutes() {
						t.Errorf("a dropped candidate recorded a %s claim; a drop is a refutation",
							c.Polarity.Effective())
					}
					if strings.TrimSpace(c.Statement) == "" {
						t.Error("a claim was recorded with an empty statement")
					}
					if c.Provenance.Source == "" || c.Provenance.Tool == "" {
						t.Errorf("claim has incomplete provenance (%+v); an unattributable "+
							"claim cannot be checked against any Authority", c.Provenance)
					}
					if strings.Contains(c.Statement, tc.wantReason) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("no recorded claim explains this drop; wanted a statement containing %q. "+
					"Recorded subjects: %v", tc.wantReason, store.Subjects())
			}
		})
	}
}

// TestRecordingChangesNoOutput is the shadow-mode guarantee. E1 records
// reasoning and changes nothing a consumer sees; if that were not true it would
// be a behaviour change wearing an observability change's clothes.
func TestRecordingChangesNoOutput(t *testing.T) {
	for _, tc := range refutationCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("writing sample: %v", err)
			}
			artifacts := []discovery.Artifact{{Path: tc.file, AbsPath: path}}

			silent := NewAnalyzer()
			quiet, err := silent.ScanArtifacts(context.Background(), artifacts)
			if err != nil {
				t.Fatalf("ScanArtifacts without a store: %v", err)
			}

			recording := NewAnalyzer()
			recording.RecordReasoningTo(reasoning.New())
			loud, err := recording.ScanArtifacts(context.Background(), artifacts)
			if err != nil {
				t.Fatalf("ScanArtifacts with a store: %v", err)
			}

			a, b := quiet.Findings(), loud.Findings()
			if len(a) != len(b) {
				t.Fatalf("recording changed the finding count: %d without a store, %d with one",
					len(a), len(b))
			}
			for i := range a {
				if a[i].Fingerprint != b[i].Fingerprint {
					t.Errorf("finding %d differs: %s vs %s", i, a[i].Fingerprint, b[i].Fingerprint)
				}
			}
		})
	}
}

// TestNilStoreRecordsNothingAndDoesNotPanic pins the property that lets the six
// call sites be unconditional. Every existing caller passes no store, so the
// nil path is the one that runs in production today.
func TestNilStoreRecordsNothingAndDoesNotPanic(t *testing.T) {
	kept, _ := scanWithReasoning(t, "config.py", "API_KEY = \"your-api-key-here\"\n")
	_ = kept

	var nilStore *reasoning.Store
	nilStore.Refute(reasoning.Candidate("SEC-001", "a.py", 1, 1), evidence.KindStatic,
		"nox-scan", "secrets", "should vanish")
	if nilStore.Len() != 0 {
		t.Error("a nil store retained a claim")
	}
	if got := nilStore.About(reasoning.Candidate("SEC-001", "a.py", 1, 1)); got.Len() != 0 {
		t.Error("a nil store returned claims")
	}
	if r, d := nilStore.Stats(); r != 0 || d != 0 {
		t.Errorf("a nil store reported stats %d/%d, want 0/0", r, d)
	}
}
