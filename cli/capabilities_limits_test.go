package main

import (
	"strings"
	"testing"
)

// A full matrix must still state what nox cannot do.
//
// The limits used to print only alongside a missing capability, which was fine
// while two were missing and became a silent regression the moment
// core/callgraph filled the last of them: every row said "provided", the
// caveats vanished, and a reader would take a complete matrix for a complete
// answer.
//
// None of these is a gap an operator can close by installing something. They
// are properties of what a scanner is, which is exactly why they cannot be
// conditional on something being absent.
func TestAFullMatrixStillStatesItsLimits(t *testing.T) {
	out := captureStdout(t, func() { runAnalysisCapabilities(nil) })

	for _, claim := range []string{
		"a scan executes nothing",
		"Go only",
		"never reports that no path exists",
	} {
		if !strings.Contains(out, claim) {
			t.Errorf("`nox analysis-capabilities` does not say %q. With nothing missing, "+
				"this output is the only place an operator is told what a full matrix "+
				"still does not mean.", claim)
		}
	}
}
