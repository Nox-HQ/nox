package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A blank line before a flagged Dockerfile instruction is semantics-preserving,
// so a finding must land on the instruction and keep a stable fingerprint. The
// pattern rules anchored with `(?im)^\s*KEYWORD`, and `\s` includes newlines, so
// under multiline matching `^\s*` began the match on the *preceding blank line*:
// the finding was reported on the blank line (a wrong location) and its matched
// content gained a leading newline, which perturbed the v2 fingerprint — a
// silent false-positive/false-negative pair under a no-op edit that also breaks
// baseline matching.
//
// Found by the metamorphic corpus oracle (scripts/metamorphic/sweep.py) on
// IAC-001 / IAC-003 / IAC-024. The fix anchors with `^[ \t]*`, which cannot
// cross a newline — the same correction #311 applied to the absence anchors.
func TestDockerfilePatternRule_BlankLineBeforeInstruction(t *testing.T) {
	cases := []struct {
		name, rule string
		noBlank    string
		withBlank  string
		// The line the instruction sits on in withBlank (1-based).
		wantLine int
	}{
		{
			name:      "IAC-001 USER root",
			rule:      "IAC-001",
			noBlank:   "FROM alpine:3.20\nRUN true\nUSER root\nCMD [\"/a\"]\n",
			withBlank: "FROM alpine:3.20\nRUN true\n\nUSER root\nCMD [\"/a\"]\n",
			wantLine:  4,
		},
		{
			name:      "IAC-003 ADD",
			rule:      "IAC-003",
			noBlank:   "FROM alpine:3.20\nADD x.tar /x\n",
			withBlank: "FROM alpine:3.20\n\nADD x.tar /x\n",
			wantLine:  3,
		},
		{
			name:      "IAC-024 sudo",
			rule:      "IAC-024",
			noBlank:   "FROM alpine:3.20\nRUN sudo apk add curl\n",
			withBlank: "FROM alpine:3.20\n\nRUN sudo apk add curl\n",
			wantLine:  3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAnalyzer()

			base, err := a.ScanFile("Dockerfile", []byte(tc.noBlank))
			if err != nil {
				t.Fatalf("scan noBlank: %v", err)
			}
			baseF := findRule(base, tc.rule)
			if baseF == nil {
				t.Fatalf("%s did not fire on the un-shifted Dockerfile", tc.rule)
			}

			got, err := a.ScanFile("Dockerfile", []byte(tc.withBlank))
			if err != nil {
				t.Fatalf("scan withBlank: %v", err)
			}
			f := findRule(got, tc.rule)
			if f == nil {
				t.Fatalf("%s disappeared when a blank line was inserted before it", tc.rule)
			}

			if f.Location.StartLine != tc.wantLine {
				t.Errorf("%s located at line %d, want %d (the instruction line, not the blank line)",
					tc.rule, f.Location.StartLine, tc.wantLine)
			}
			if f.Fingerprint != baseF.Fingerprint {
				t.Errorf("%s fingerprint changed under a semantics-preserving blank-line insert\n  before=%s\n   after=%s\n(this breaks baseline matching)",
					tc.rule, baseF.Fingerprint, f.Fingerprint)
			}
		})
	}
}

func findRule(results []findings.Finding, ruleID string) *findings.Finding {
	for i := range results {
		if results[i].RuleID == ruleID {
			return &results[i]
		}
	}
	return nil
}
