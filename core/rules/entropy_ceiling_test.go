package rules

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// A high-entropy run has to stop being a credential at some length.
//
// There was no ceiling. Measured on crewAI's recorded cassettes, the entropy
// rules produced findings with spans of 8,192 and 37,392 characters -- base64
// response bodies reported as "possible secret" -- and 67 of 507 entropy
// findings there ran past 2,048.
//
// The number is derived, not chosen. The longest credential any rule in the
// shipped set models is 1,000 characters (SEC-302) and the 99th percentile
// across all 1,423 length quantifiers is 135, so 2,048 is twice the longest
// format anyone has written down.
//
// Verified against the real surface rather than a fixture: re-scanning the
// cassettes with the ceiling dropped 67 findings, added 0, and the shortest
// span among the dropped was 2,580. Nothing below the ceiling was lost.

// entropyRule builds an assignment-scoped entropy rule.
func entropyRule() *Rule {
	return &Rule{
		ID: "TEST-ENTROPY", MatcherType: "entropy",
		Metadata: map[string]string{
			"entropy_threshold": "3.0",
			"candidate_kinds":   string(candidateQuoted),
		},
	}
}

// highEntropyToken returns n characters with no short-period repetition, so the
// token's own shape is never the reason a test fails.
func highEntropyToken(n int) string {
	const alphabet = "aZ3xQ7mK9pR2wL5vN8tB4yH6jD0sF1gC"
	r := rand.New(rand.NewSource(int64(n)))
	var b strings.Builder
	for b.Len() < n {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()[:n]
}

func TestAnEntropyCandidateStopsAtCredentialLength(t *testing.T) {
	t.Parallel()

	m := &EntropyMatcher{}
	rule := entropyRule()

	for _, tc := range []struct {
		name string
		n    int
		want bool
	}{
		{"an ordinary key", 40, true},
		{"the longest credential any rule models", 1000, true},
		{"just under the ceiling", maxCandidateLen - 8, true},
		{"just over it", maxCandidateLen + 8, false},
		{"a base64 response body", 37392, false},
	} {
		content := fmt.Sprintf("token = %q\n", highEntropyToken(tc.n))
		got := len(m.Match([]byte(content), rule)) > 0
		if got != tc.want {
			verb := "did not fire"
			if got {
				verb = "fired"
			}
			t.Errorf("%s (%d chars): %s, wanted the opposite", tc.name, tc.n, verb)
		}
	}
}

// TestTheCeilingBoundsTheCandidateNotTheFile is the recall half. A credential
// does not become invisible because the file around it is large -- only the run
// itself has to be credential-sized, or a 40-character key inside a 2MB
// cassette would be lost, which is the case this whole surface exists for.
func TestTheCeilingBoundsTheCandidateNotTheFile(t *testing.T) {
	t.Parallel()

	padding := strings.Repeat("# ordinary line of source\n", 20000)
	content := padding + fmt.Sprintf("token = %q\n", highEntropyToken(40)) + padding

	if len(content) < 4*maxCandidateLen {
		t.Fatalf("padding is too small to test the distinction (%d bytes)", len(content))
	}
	if got := (&EntropyMatcher{}).Match([]byte(content), entropyRule()); len(got) == 0 {
		t.Errorf("a 40-character credential in a %d-byte file was not reported; the ceiling is "+
			"bounding the file rather than the candidate", len(content))
	}
}
