package ai

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

// aiRefutationCases covers the drops in the AI analyzer's refinement loop.
//
// The kinds differ between them and that is deliberate: a lexer region is
// deterministic, a proximity check is not, and a ledger that recorded them at
// the same strength would assert more than either established.
var aiRefutationCases = []struct {
	name       string
	file       string
	content    string
	wantReason string
	wantKind   evidence.Kind
}{
	{
		name:       "constant log message containing the word prompt",
		file:       "cli.go",
		content:    "package p\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc F() {\n\tfmt.Fprintln(os.Stderr, \"nobody can approve a browser prompt.\")\n}\n",
		wantReason: "every argument to the logging call is constant text",
		wantKind:   evidence.KindStatic,
	},
}

// TestAIDropsRecordTheirReason is E2: the constant-argument refutation that
// commit 0810e63 implemented as an in-rule guard is now recorded as evidence,
// so the reason a candidate was dropped survives the dropping.
func TestAIDropsRecordTheirReason(t *testing.T) {
	for _, tc := range aiRefutationCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			store := reasoning.New()
			a := NewAnalyzer()
			a.RecordReasoningTo(store)

			if _, _, err := a.ScanArtifacts(context.Background(),
				[]discovery.Artifact{{Path: tc.file, AbsPath: path}}); err != nil {
				t.Fatalf("ScanArtifacts: %v", err)
			}

			recorded, unusable := store.Stats()
			if unusable != 0 {
				t.Errorf("%d claim(s) filed against an unusable subject", unusable)
			}
			if recorded == 0 {
				t.Fatal("a candidate was dropped and nothing was recorded about it")
			}

			var found bool
			for _, subject := range store.Subjects() {
				for _, c := range store.About(subject).Claims {
					if !c.Refutes() {
						t.Errorf("a dropped candidate recorded a %s claim", c.Polarity.Effective())
					}
					if c.Provenance.Tool != "ai" {
						t.Errorf("claim attributed to tool %q, want ai", c.Provenance.Tool)
					}
					if strings.Contains(c.Statement, tc.wantReason) {
						found = true
						if c.Kind != tc.wantKind {
							t.Errorf("recorded kind %q, want %q — how a claim was "+
								"established is what Kind means, and a proximity check "+
								"is not a lexer", c.Kind, tc.wantKind)
						}
					}
				}
			}
			if !found {
				t.Errorf("no claim explains the drop; wanted a statement containing %q", tc.wantReason)
			}
		})
	}
}

// TestAIRecordingChangesNoOutput. Shadow mode, at analyzer level.
func TestAIRecordingChangesNoOutput(t *testing.T) {
	for _, tc := range aiRefutationCases {
		dir := t.TempDir()
		path := filepath.Join(dir, tc.file)
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		artifacts := []discovery.Artifact{{Path: tc.file, AbsPath: path}}

		quiet, _, err := NewAnalyzer().ScanArtifacts(context.Background(), artifacts)
		if err != nil {
			t.Fatalf("scan without store: %v", err)
		}
		rec := NewAnalyzer()
		rec.RecordReasoningTo(reasoning.New())
		loud, _, err := rec.ScanArtifacts(context.Background(), artifacts)
		if err != nil {
			t.Fatalf("scan with store: %v", err)
		}
		if len(quiet.Findings()) != len(loud.Findings()) {
			t.Errorf("%s: recording changed the finding count: %d vs %d",
				tc.name, len(quiet.Findings()), len(loud.Findings()))
		}
	}
}
