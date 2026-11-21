package taintflow

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// A query built from a parameter is reported, but not as untrusted input: no
// source in the file shows that a caller passes request data. The finding says
// what was shown, and is low confidence, so a `--min-confidence medium` gate
// keeps its answer.
func TestAQueryBuiltFromAParameterIsALowConfidenceFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "dao.py", `def login(cursor, username):
    return cursor.execute("SELECT * FROM users WHERE username = '%s'" % username).fetchone()
`)
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	items := fs.Findings()
	if len(items) != 1 {
		t.Fatalf("want one finding, got %d: %+v", len(items), items)
	}
	f := items[0]
	if f.RuleID != "TAINT-001" || f.Confidence != findings.ConfidenceLow || f.Location.StartLine != 2 {
		t.Errorf("got %s confidence %s at line %d, want TAINT-001 low at 2", f.RuleID, f.Confidence, f.Location.StartLine)
	}
	if f.Metadata["source_kind"] != "parameter" || f.Metadata["source_var"] != "username" {
		t.Errorf("metadata does not name the parameter: %v", f.Metadata)
	}
	if strings.Contains(f.Message, "Untrusted input (") || !strings.Contains(f.Message, `parameter "username" of login`) {
		t.Errorf("message claims more or less than was shown: %s", f.Message)
	}
}
