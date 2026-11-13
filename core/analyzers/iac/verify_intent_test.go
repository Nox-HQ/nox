package iac

import (
	"strings"
	"testing"
)

// A "verify intent" rule reports something that is fine once someone has
// checked it. The remediation must say how to record that the check was done,
// or the finding is reported on every scan forever and the only way to quiet
// it is to stop running the rule (#1011).
func TestVerifyIntentRulesNameTheirWaiver(t *testing.T) {
	n := 0
	for _, r := range builtinIaCRules() {
		if !strings.Contains(strings.ToLower(r.Description), "verify intent") {
			continue
		}
		n++
		if want := "nox:ignore " + r.ID + " -- "; !strings.Contains(r.Remediation, want) {
			t.Errorf("%s says to verify intent but its remediation does not show the waiver %q", r.ID, want)
		}
	}
	if n == 0 {
		t.Fatal("no verify-intent rules found; the test checks nothing")
	}
}
