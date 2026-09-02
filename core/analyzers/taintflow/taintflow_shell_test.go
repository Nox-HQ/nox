package taintflow

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// A source used directly as the sink's argument binds no variable. The message
// used to render that as `via ""`; it now names the source expression.
func TestAnalyzerShellInlineSourceMessage(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "run.sh", "#!/bin/sh\neval \"$@\"\n")
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	items := fs.Findings()
	if len(items) != 1 || items[0].RuleID != "TAINT-005" {
		t.Fatalf("want one TAINT-005, got %+v", items)
	}
	msg := items[0].Message
	if strings.Contains(msg, `via ""`) || !strings.Contains(msg, `argv from "$@" used directly`) {
		t.Fatalf("message does not name the inline source: %q", msg)
	}
}
