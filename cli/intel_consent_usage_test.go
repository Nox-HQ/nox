package main

import (
	"bytes"
	"strings"
	"testing"
)

// An unknown subcommand prints the usage, and the usage names every consent
// scope. It once listed contribution and attack but not outcomes, so a user
// typing `consent outcomes` on a build without it, or a typo, was never told
// the scope exists.
func TestConsentUsageNamesEveryScope(t *testing.T) {
	var out, errw bytes.Buffer
	if code := intelConsent([]string{"no-such-subcommand"}, strings.NewReader(""), &out, &errw); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	for _, scope := range []string{"nox intel consent [", "nox intel consent attack [", "nox intel consent outcomes ["} {
		if !strings.Contains(errw.String(), scope) {
			t.Errorf("usage does not name %q:\n%s", scope, errw.String())
		}
	}
}
