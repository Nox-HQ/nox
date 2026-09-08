package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// scanned puts a real scan of the precision suite into the server's cache, the
// way the scan tool would.
func scanned(t *testing.T) *Server {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := nox.RunScanWithOptions("../testdata/precision-suite",
		nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	s := New("test", nil)
	s.setCache("", res)
	return s
}

func payload(t *testing.T, r any) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestAnAgentCanLearnWhatWasNotEvaluated is the gap this tool closes.
//
// The MCP surface already carried degradations, which say that a check BROKE.
// Nothing said a question was never ASKED, and an agent reading a clean finding
// list had no way to tell the two apart — so "no findings" read as "nothing is
// wrong". Track D exists for that distinction and it stopped at the CLI.
func TestAnAgentCanLearnWhatWasNotEvaluated(t *testing.T) {
	s := scanned(t)
	res, err := s.handleAnalysisCapabilities(context.Background(), emptyInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	out := payload(t, res)

	var report capabilityOutput
	decode(t, res, &report)
	if len(report.Capabilities) == 0 {
		t.Fatal("the capability report is empty")
	}

	// Assert on the ROW, not on the covering note. An earlier version of this
	// test matched a phrase that only ever appeared in the note, so a row could
	// describe an unasked question as "no issues found" and the test still
	// passed — a guard reading the reassurance instead of the claim. Found by
	// falsifying it and watching nothing fail.
	var sawUnasked bool
	for _, row := range report.Capabilities {
		switch {
		case !row.Provided:
			if !strings.Contains(row.Meaning, "Nothing on this installation can establish it") {
				t.Errorf("%s is unprovided but its meaning reads %q", row.Capability, row.Meaning)
			}
		case row.Answered == 0 && row.Inconclusive == 0:
			sawUnasked = true
			if !strings.Contains(row.Meaning, "nothing in this scan put the question") {
				t.Errorf("%s was never asked but its meaning reads %q — an agent "+
					"summarising this would report it as checked", row.Capability, row.Meaning)
			}
		}
	}
	// The unprovided branch is no longer reachable through a real scan —
	// core/callgraph filled the last capability nothing implemented — so it is
	// exercised directly in TestEveryCapabilityMeaningIsDistinct rather than
	// left as an arm that happens never to run. Only the branch a scan can
	// still reach is required here.
	if !sawUnasked {
		t.Error("the corpus exercised no unasked capability, so the assertion above is vacuous")
	}
	// Never a clearance. An agent summarising this must not be handed a word
	// that lets it write "no issues".
	for _, banned := range []string{"\"safe\"", "no risk", "not vulnerable"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("the capability report contains %q", banned)
		}
	}
}

// TestAnAgentCanAskWhy. The two questions worth the round trip are the ones a
// scanner normally omits, so they are the ones checked here.
func TestAnAgentCanAskWhy(t *testing.T) {
	s := scanned(t)
	res, err := s.handleWhy(context.Background(), whyInput{Fingerprint: "SEC-003"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	out := payload(t, res)

	for _, want := range []string{
		"not_evaluated", "affects_this_application", "supports", "what_to_do",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the explanation omits %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no active finding matches") {
		t.Fatalf("selecting by rule ID matched nothing; the shared selector is not "+
			"being used:\n%s", out)
	}
}

// TestWhyResolvesTheSameSelectorAsTheCLI. A person who gets a fingerprint
// prefix from `nox scan` and hands it to an agent must have it resolve. The two
// surfaces each grew their own prefix match once and drifted on case; this
// pins that they now share one.
func TestWhyResolvesTheSameSelectorAsTheCLI(t *testing.T) {
	s := scanned(t)
	pc := s.getCache("")
	if pc == nil {
		t.Fatal("no cache")
	}
	all := pc.result.Findings.ActiveFindings()
	if len(all) == 0 {
		t.Fatal("no findings to select")
	}
	full := all[0].Fingerprint

	for _, sel := range []string{full, full[:12], strings.ToUpper(full[:12])} {
		res, err := s.handleWhy(context.Background(), whyInput{Fingerprint: sel})
		if err != nil {
			t.Fatalf("handler(%q): %v", sel, err)
		}
		if strings.Contains(payload(t, res), "no active finding matches") {
			t.Errorf("selector %q resolved nothing; the CLI accepts it", sel)
		}
	}
}

// TestWhySaysSoWhenThereIsNoEvidence. A scan that recorded no reasoning must
// report that, not return an explanation with empty support that reads as
// "nothing backs this finding".
func TestWhySaysSoWhenThereIsNoEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := nox.RunScanWithOptions("../testdata/precision-suite", nox.ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	s := New("test", nil)
	s.setCache("", res)

	got, err := s.handleWhy(context.Background(), whyInput{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(payload(t, got), "recorded no reasoning") {
		t.Errorf("a scan with no evidence did not say so:\n%s", payload(t, got))
	}
}

// TestFingerprintLookupAcceptsWhatTheCLIAccepts covers the second surface that
// shares the selector.
//
// It exists because falsifying the first selector test proved nothing:
// reverting get_finding_by_fingerprint to its own case-sensitive prefix match
// failed no test, because `why` had coverage and this tool had none. A shared
// helper with one caller tested is still two implementations as far as the
// evidence goes.
func TestFingerprintLookupAcceptsWhatTheCLIAccepts(t *testing.T) {
	s := scanned(t)
	all := s.getCache("").result.Findings.ActiveFindings()
	if len(all) == 0 {
		t.Fatal("no findings to select")
	}
	full := all[0].Fingerprint

	for _, sel := range []string{full, full[:12], strings.ToUpper(full[:12])} {
		res, err := s.handleFindingByFingerprint(context.Background(),
			findingByFingerprintInput{Fingerprint: sel})
		if err != nil {
			t.Fatalf("handler(%q): %v", sel, err)
		}
		if !strings.Contains(payload(t, res), `"found":true`) {
			t.Errorf("get_finding_by_fingerprint(%q) found nothing; the CLI accepts it, "+
				"so a person moving between the two surfaces sees the finding vanish", sel)
		}
	}
}

func decode(t *testing.T, r, into any) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(b, &envelope); err == nil {
		for _, key := range []string{"structuredContent", "structured_content", "content"} {
			if raw, ok := envelope[key]; ok {
				if err := json.Unmarshal(raw, into); err == nil {
					return
				}
			}
		}
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("could not decode structured result: %v\n%s", err, b)
	}
}

// Every branch of capabilityMeaning, exercised directly.
//
// The scan-driven test above can no longer reach the unprovided arm, and an
// assertion inside a branch that never runs is not an assertion. The wording is
// what an agent reads when summarising a scan, so each case has to say
// something different — and none of them may say a gap was a clean result.
func TestEveryCapabilityMeaningIsDistinct(t *testing.T) {
	cases := []struct {
		name         string
		provided     bool
		answered     int
		inconclusive int
		want         string
	}{
		{"unprovided", false, 0, 0, "Nothing on this installation can establish it"},
		{"answered", true, 3, 0, "Established for some findings"},
		{"inconclusive", true, 0, 2, "ran and could not determine anything"},
		{"unasked", true, 0, 0, "nothing in this scan put the question"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		got := capabilityMeaning(tc.provided, tc.answered, tc.inconclusive)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: meaning %q does not contain %q", tc.name, got, tc.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s render the same sentence %q; two different states an "+
				"operator must respond to differently are being reported identically",
				tc.name, prev, got)
		}
		seen[got] = tc.name
		for _, banned := range []string{"safe", "no issues", "not vulnerable", "clean"} {
			if strings.Contains(strings.ToLower(got), banned) {
				t.Errorf("%s: meaning %q contains %q, which reads as a clearance",
					tc.name, got, banned)
			}
		}
	}
}
