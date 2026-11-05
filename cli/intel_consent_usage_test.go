package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/intel"
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

// Plain `nox intel consent` reports every scope. It looked only at the
// contribution terms and said "No terms accepted on this machine" to an owner
// whose outcome terms were accepted and stored beside them.
func TestConsentStatusReportsEveryScope(t *testing.T) {
	salt := filepath.Join(t.TempDir(), "reporter-salt")
	if err := intel.RecordOutcomeConsent(salt, "2026-11-04T12:13:55Z"); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	if code := intelConsent([]string{"status", "-salt-path", salt}, strings.NewReader(""), &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	got := out.String()
	if strings.Contains(got, "No terms accepted on this machine") {
		t.Errorf("status denies an acceptance it holds:\n%s", got)
	}
	for _, want := range []string{"Outcome terms " + intel.OutcomeTermsVersion + " accepted at 2026-11-04T12:13:55Z", "contribution", "attack"} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("status does not report %q:\n%s", want, got)
		}
	}
}

// A scope typed after the verb (`consent show outcomes`) printed the
// contribution terms and ignored the word. It is refused, naming the order
// that works.
func TestConsentVerbBeforeScopeIsRefused(t *testing.T) {
	for _, scope := range []string{"outcomes", "attack"} {
		var out, errw bytes.Buffer
		code := intelConsent([]string{"show", scope}, strings.NewReader(""), &out, &errw)
		if code != 2 || out.Len() != 0 {
			t.Errorf("show %s: exit %d, printed %d bytes; want a refusal", scope, code, out.Len())
		}
		if want := "nox intel consent " + scope + " show"; !strings.Contains(errw.String(), want) {
			t.Errorf("show %s: error %q does not name %q", scope, errw.String(), want)
		}
	}
}
