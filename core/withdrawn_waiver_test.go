package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// An operator who waived a rule nox has since RETRACTED used to be told the
// finding "may have been fixed" and to "check the rule ID". Both are wrong: the
// finding was not fixed, and the ID is not a typo. The advice sends them
// looking for something that cannot exist.
//
// withdrawnWaiverNote is what turns that into a sentence they can act on.

func TestAWaiverOnAWithdrawnRuleExplainsItself(t *testing.T) {
	t.Parallel()

	ids := rules.WithdrawnIDs()
	if len(ids) == 0 {
		t.Fatal("no withdrawn rules registered; this test would pass vacuously")
	}
	id := ids[0]
	w, _ := rules.Withdrawn(id)

	note := withdrawnWaiverNote([]string{id})
	if note == "" {
		t.Fatalf("a waiver naming the withdrawn rule %s produced no explanation", id)
	}
	for _, want := range []string{id, w.Version, "withdrawn"} {
		if !strings.Contains(note, want) {
			t.Errorf("the explanation for %s omits %q:\n%s", id, want, note)
		}
	}
	// It has to say what to DO, or it is just a longer silence.
	if !strings.Contains(note, "can be deleted") {
		t.Errorf("the explanation for %s does not say what to do with the waiver:\n%s", id, note)
	}
}

func TestAWaiverOnALiveRuleGetsTheOrdinaryAdvice(t *testing.T) {
	t.Parallel()

	// A live or merely-retired rule must fall through to the generic
	// unused-waiver message: claiming it was withdrawn would be false, and
	// retirement keeps the condition reported under a survivor.
	for _, id := range []string{"SEC-001", "SEC-454", "IAC-013"} {
		if note := withdrawnWaiverNote([]string{id}); note != "" {
			t.Errorf("%s is not withdrawn but got a withdrawal note: %s", id, note)
		}
	}
}

// The unused-waiver check runs on two paths: a sweep over files with no finding
// at all, and a per-file pass over files that DO have findings. Only the sweep
// consulted the tombstone registry. A waiver naming a withdrawn rule in a file
// with any other finding — the common case in a real codebase — got the generic
// "matched no finding" advice, which is wrong for it in both directions.
//
// TestAWaiverOnAWithdrawnRuleExplainsItself tested the helper and so could not
// see that one caller never called it. This drives both paths through a scan.
// It was found by verifying the v1.38.0 release binary, which had to be
// withdrawn before it published; v1.37.0 shipped with the same gap.
func TestBothUnusedWaiverPathsExplainAWithdrawal(t *testing.T) {
	cases := map[string]string{
		// No finding in the file: the sweep path.
		"clean file": "r = chat(temperature=1.0)  # nox:ignore AI-022\n",
		// SLOP-001 fires on the import, so the file takes the per-file path.
		"file with another finding": "import openai\nr = openai.chat(temperature=1.0)  # nox:ignore AI-022\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, d := range res.Degradations {
				if strings.Contains(d.Detail, "AI-022") {
					got = append(got, d.Detail)
				}
			}
			if len(got) != 1 {
				t.Fatalf("want exactly one degradation about the AI-022 waiver, got %q", got)
			}
			if !strings.Contains(got[0], "which was withdrawn") {
				t.Errorf("the waiver got generic advice instead of the withdrawal explanation: %q", got[0])
			}
		})
	}
}
