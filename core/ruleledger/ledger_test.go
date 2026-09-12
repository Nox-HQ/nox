package ruleledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ledgerPath is the real file, relative to this package.
const ledgerPath = "../../scripts/rule-deltas.json"

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rule-deltas.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTheCommittedLedgerIsWellFormed. The checks below are only worth anything
// if the file they guard passes them.
func TestTheCommittedLedgerIsWellFormed(t *testing.T) {
	l, err := Load(ledgerPath)
	if err != nil {
		t.Fatalf("the committed ledger does not load: %v", err)
	}
	for _, e := range l.CheckWellFormed() {
		t.Error(e)
	}
}

// TestARolledLedgerPassesItsRelease checks the happy path: entries cleared and
// nox_release advanced to the tag being cut.
func TestARolledLedgerPassesItsRelease(t *testing.T) {
	p := write(t, `{"nox_release":"v1.36.0","classifications":{"x":"y"},"entries":[]}`)
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CheckForRelease("v1.36.0"); err != nil {
		t.Errorf("a cleared ledger at the right release failed: %v", err)
	}
}

// TestAnUnrolledLedgerFailsTheRelease is the case that actually happened:
// v1.35.0 shipped with sixteen entries still explaining drops from v1.34.0.
func TestAnUnrolledLedgerFailsTheRelease(t *testing.T) {
	p := write(t, `{"nox_release":"v1.34.0","classifications":{"refined-away":"d"},
	  "entries":[{"rule":"IAC-132","classification":"refined-away","reason":"r"},
	             {"rule":"IAC-142","classification":"refined-away","reason":"r"}]}`)
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	err = l.CheckForRelease("v1.35.0")
	if err == nil {
		t.Fatal("a release cut with a stale ledger and leftover entries passed")
	}
	msg := err.Error()
	for _, want := range []string{"v1.34.0", "v1.35.0", "IAC-132", "IAC-142"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q, so the releaser cannot act on it:\n%s", want, msg)
		}
	}
}

// TestEachHalfOfTheRollIsRequiredOnItsOwn. Advancing nox_release while leaving
// the entries, or clearing the entries while leaving the version, each produce a
// ledger that reads as rolled and is not.
func TestEachHalfOfTheRollIsRequiredOnItsOwn(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{
			name: "version advanced, entries left behind",
			body: `{"nox_release":"v1.36.0","classifications":{"c":"d"},
			        "entries":[{"rule":"SEC-696","classification":"c","reason":"r"}]}`,
			want: "SEC-696",
		},
		{
			name: "entries cleared, version left behind",
			body: `{"nox_release":"v1.35.0","classifications":{},"entries":[]}`,
			want: "v1.35.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Load(write(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			err = l.CheckForRelease("v1.36.0")
			if err == nil {
				t.Fatal("half a roll passed as a whole one")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("failure does not name %q: %v", tc.want, err)
			}
		})
	}
}

// TestMalformedEntriesAreNamed checks that each way an entry can explain
// nothing is reported separately.
func TestMalformedEntriesAreNamed(t *testing.T) {
	l, err := Load(write(t, `{"nox_release":"v1","classifications":{"known":"d"},
	  "entries":[{"rule":"A","classification":"known","reason":""},
	             {"rule":"B","classification":"invented","reason":"r"},
	             {"rule":"","classification":"known","reason":"r"},
	             {"rule":"A","classification":"known","reason":"r"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	errs := l.CheckWellFormed()
	if len(errs) < 4 {
		t.Errorf("expected an empty reason, an unknown classification, a missing rule "+
			"and a duplicate to each be reported; got %d: %v", len(errs), errs)
	}
}

// TestTheReleaseInvariant runs against the tag being cut.
//
// The release workflow sets NOX_RELEASE_TAG. Everywhere else this is skipped:
// during development the ledger is SUPPOSED to carry entries, and asserting
// otherwise would make the file unusable for the thing it exists for.
func TestTheReleaseInvariant(t *testing.T) {
	tag := os.Getenv("NOX_RELEASE_TAG")
	if tag == "" {
		t.Skip("not a release; set NOX_RELEASE_TAG to run the release-time invariant")
	}
	l, err := Load(ledgerPath)
	if err != nil {
		t.Fatalf("the ledger does not load, so the release cannot be checked: %v", err)
	}
	for _, e := range l.CheckWellFormed() {
		t.Error(e)
	}
	if err := l.CheckForRelease(tag); err != nil {
		t.Fatal(err)
	}
}
