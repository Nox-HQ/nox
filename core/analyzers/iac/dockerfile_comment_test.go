package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The Dockerfile "missing instruction" rules (IAC-121 HEALTHCHECK, IAC-124
// LABEL maintainer) are absence rules: they fire when the instruction is not
// present in the file. Their AbsenceProperty matched the bare keyword anywhere
// in the file, including inside a comment — so a Dockerfile that merely
// *mentions* the instruction in a comment silently satisfied the rule and the
// finding disappeared.
//
// This is a false negative in a security scanner: `# TODO: add a HEALTHCHECK`
// makes nox stop reporting the missing HEALTHCHECK. A real instruction begins a
// line, so the property must be anchored the way the sibling rules (IAC-122
// USER, IAC-125 CMD) already are.
//
// Found while getting nox's own repo to badge grade A: a waiver comment reading
// "a HEALTHCHECK has nothing to poll" disabled IAC-121 on nox's Dockerfile, and
// nox correctly reported the waiver as suppressing nothing — the waiver was
// redundant because the rule had already been silenced by its own keyword.
func TestDockerfileAbsenceRule_KeywordInCommentDoesNotSatisfy(t *testing.T) {
	cases := []struct {
		name   string
		ruleID string
		// A Dockerfile with the instruction genuinely absent, but mentioned in
		// a comment. The finding must still fire.
		commentedOut string
		// The same Dockerfile with the instruction genuinely present. The
		// finding must NOT fire — this guards against over-correcting into a
		// false positive.
		instructionPresent string
	}{
		{
			name:   "IAC-121 HEALTHCHECK",
			ruleID: "IAC-121",
			commentedOut: `FROM alpine:3.20
# no HEALTHCHECK is needed for a one-shot CLI
USER nobody
ENTRYPOINT ["/app"]
`,
			instructionPresent: `FROM alpine:3.20
HEALTHCHECK --interval=30s CMD /app healthz || exit 1
USER nobody
ENTRYPOINT ["/app"]
`,
		},
		{
			name:   "IAC-124 LABEL maintainer",
			ruleID: "IAC-124",
			commentedOut: `FROM alpine:3.20
# LABEL maintainer is deprecated; we use OCI image labels instead
USER nobody
`,
			instructionPresent: `FROM alpine:3.20
LABEL maintainer="team@example.com"
USER nobody
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAnalyzer()

			got, err := a.ScanFile("Dockerfile", []byte(tc.commentedOut))
			if err != nil {
				t.Fatalf("scan commentedOut: %v", err)
			}
			if !hasRule(got, tc.ruleID) {
				t.Errorf("%s did not fire when the instruction was only mentioned in a comment; "+
					"the absence rule is matching its keyword inside comments", tc.ruleID)
			}

			got, err = a.ScanFile("Dockerfile", []byte(tc.instructionPresent))
			if err != nil {
				t.Fatalf("scan instructionPresent: %v", err)
			}
			if hasRule(got, tc.ruleID) {
				t.Errorf("%s fired even though the instruction is genuinely present; "+
					"the anchoring is too strict", tc.ruleID)
			}
		})
	}
}

// A blank line before an instruction must not change whether an absence rule
// fires. The anchors used `^\s*COPY…`, and `\s` includes newlines, so in
// multiline mode the match began on the preceding blank line. Line-span rules
// (IAC-123) then computed their span from that blank line, which contains no
// --chown, and the rule fired on a COPY that was correctly chowned — a false
// positive on ordinary Dockerfiles, since a blank line before a COPY is
// idiomatic.
func TestDockerfileAbsenceRule_BlankLineBeforeInstruction(t *testing.T) {
	a := NewAnalyzer()

	// COPY has --chown and is preceded by a blank line: IAC-123 must NOT fire.
	withBlank := `FROM scratch
LABEL org.opencontainers.image.title="x"

COPY --from=b --chown=nonroot:nonroot /a /b
`
	got, err := a.ScanFile("Dockerfile", []byte(withBlank))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasRule(got, "IAC-123") {
		t.Error("IAC-123 fired on a COPY that has --chown, because a blank line " +
			"before it shifted the anchor onto the blank line")
	}

	// A COPY genuinely missing --chown must still fire, blank line or not.
	missing := `FROM scratch

COPY /a /b
`
	got, err = a.ScanFile("Dockerfile", []byte(missing))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !hasRule(got, "IAC-123") {
		t.Error("IAC-123 did not fire on a COPY missing --chown; the anchor fix over-corrected")
	}
}

// The same comment-keyword class as IAC-121, but through a YAML trailing
// comment rather than a Dockerfile line. IAC-153 fires when an artifact upload
// has no attestation; its property is the bare keyword `(?i)attest`, matched
// over the whole file. A trailing comment containing "attest" (a nox:ignore
// reason, a note) satisfied it and silenced the rule. Anchoring does not apply
// to a free keyword, so this is fixed by stripping comments before the
// property match — see core/rules stripLineComments.
func TestWorkflowAbsenceRule_KeywordInTrailingCommentDoesNotSatisfy(t *testing.T) {
	a := NewAnalyzer()

	// Upload step with no attestation, but a comment mentions "attested".
	// IAC-153 must still fire.
	commented := `on: [push]
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@abc123 # artifacts are attested in release.yml
`
	got, err := a.ScanFile(".github/workflows/ci.yml", []byte(commented))
	if err != nil {
		t.Fatalf("scan commented: %v", err)
	}
	if !hasRule(got, "IAC-153") {
		t.Error("IAC-153 did not fire when 'attested' appeared only in a trailing comment")
	}

	// A genuine attestation step present: IAC-153 must NOT fire.
	present := `on: [push]
jobs:
  build:
    steps:
      - uses: actions/attest-build-provenance@abc123
      - uses: actions/upload-artifact@abc123
`
	got, err = a.ScanFile(".github/workflows/ci.yml", []byte(present))
	if err != nil {
		t.Fatalf("scan present: %v", err)
	}
	if hasRule(got, "IAC-153") {
		t.Error("IAC-153 fired even though a real attestation step is present")
	}
}

func hasRule(results []findings.Finding, ruleID string) bool {
	for _, r := range results {
		if r.RuleID == ruleID {
			return true
		}
	}
	return false
}
