package deps

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A dependency finding's fingerprint is what a baseline entry, a waiver and a
// VEX statement are keyed on. Since the first release it has been the hash of
// the rule, the lockfile place and the finding's message, so it moves whenever
// the message is reworded: rewriting the applicability sentence in plain
// language changed all 59 dependency fingerprints on certbot, and every one of
// them would have come back as a new finding in a project that had baselined
// it.
//
// The messages below are what nox 1.65.0 printed for these inputs, taken from
// that release's code and not from this one. The fingerprint must stay the
// hash of exactly that text however the message a person reads is worded.
func TestDependencyFingerprintIsWhatV1_65Computed(t *testing.T) {
	const sentence = ` — established as far as "affected_version"; symbol_used was not established (unsupported — this analysis cannot apply here)`
	tests := []struct {
		name     string
		summary  string
		released string
	}{
		{
			name:     "summary",
			summary:  "Remote code execution",
			released: "Known vulnerability GHSA-fp-0001 in leftpad@1.0.0: Remote code execution" + sentence,
		},
		{
			name:     "no summary",
			summary:  "",
			released: "Known vulnerability GHSA-fp-0001 in leftpad@1.0.0: " + sentence,
		},
		{
			name:     "padded summary",
			summary:  "  Remote code execution ",
			released: "Known vulnerability GHSA-fp-0001 in leftpad@1.0.0:   Remote code execution " + sentence,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeOSV(t,
				map[string][]string{"leftpad": {"GHSA-fp-0001"}},
				map[string]string{"GHSA-fp-0001": `{
					"id": "GHSA-fp-0001",
					"summary": "` + tc.summary + `",
					"database_specific": {"severity": "HIGH"}
				}`})
			defer srv.Close()

			f := onlyVuln(t, scanOneNPMPackage(t, srv, "leftpad", "1.0.0"))
			want := findings.ComputeFingerprint("VULN-001", f.Location, tc.released)
			if f.Fingerprint != want {
				t.Errorf("fingerprint = %s\nwant the hash of the 1.65.0 message, %s\nmessage now: %q\nmessage then: %q",
					f.Fingerprint, want, f.Message, tc.released)
			}
		})
	}
}

// The other half: the message a person reads is the reworded one. Keeping the
// fingerprint by keeping the old sentence would be the wrong fix.
func TestDependencyMessageStaysInPlainLanguage(t *testing.T) {
	srv := fakeOSV(t,
		map[string][]string{"leftpad": {"GHSA-fp-0001"}},
		map[string]string{"GHSA-fp-0001": `{"id": "GHSA-fp-0001", "summary": "", "database_specific": {"severity": "HIGH"}}`})
	defer srv.Close()

	f := onlyVuln(t, scanOneNPMPackage(t, srv, "leftpad", "1.0.0"))
	for _, identifier := range []string{"affected_version", "symbol_used", "call_reachable", "attacker_reachable", "established as far as"} {
		if strings.Contains(f.Message, identifier) {
			t.Errorf("message prints %q, the ladder's own name for a step: %q", identifier, f.Message)
		}
	}
	if strings.Contains(f.Message, ":  —") || strings.Contains(f.Message, ": —") {
		t.Errorf("message has a colon in front of nothing: %q", f.Message)
	}
}

func onlyVuln(t *testing.T, items []findings.Finding) findings.Finding {
	t.Helper()
	var found []findings.Finding
	for i := range items {
		if items[i].RuleID == "VULN-001" {
			found = append(found, items[i])
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d VULN-001 findings, want 1", len(found))
	}
	return found[0]
}
