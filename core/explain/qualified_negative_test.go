package explain_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/explain"
)

// refutation builds a claim against the base fixture's subject.
func refutation(statement string, attrs map[string]string) evidence.Claim {
	return evidence.Claim{
		Kind:       evidence.KindStatic,
		Statement:  statement,
		Polarity:   evidence.PolarityRefutes,
		Subject:    subject(),
		Attributes: attrs,
		Provenance: evidence.Provenance{Source: "nox-scan", Tool: "taint"},
	}
}

// No path through the renderer can produce an unqualified negative.
//
// A refutation is a UNIVERSAL claim — "this does not hold" — and it is only as
// good as the search behind it. reach.Result has always rendered its negatives
// that way; a ledger refutation rendered as a bare sentence, which reads as
// settled.
//
// The table walks every combination a refiner can produce, including the one
// where it recorded no scope at all. That case still has to be qualified,
// generically, because "some limit exists" is the least a reader is owed.
func TestNoNegativeRendersUnqualified(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]string
	}{
		{"scope and limits", map[string]string{
			"scope": "the python taint engine, over this file", "limits": "interface dispatch",
		}},
		{"scope only", map[string]string{"scope": "YAML comment lexing"}},
		{"limits only", map[string]string{"limits": "another file"}},
		{"neither", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInputs()
			in.Ledger = evidence.Ledger{Claims: []evidence.Claim{
				refutation("a sanitizer cleared this value", tc.attrs),
			}}
			joined := strings.Join(explain.Explain(in).Against, "\n")

			if !strings.Contains(joined, "a sanitizer cleared this value") {
				t.Fatalf("the refutation is missing entirely: %q", joined)
			}
			if !strings.Contains(joined, "could see") && !strings.Contains(joined, "cannot see") {
				t.Errorf("the negative renders unqualified: %q. A refutation that reads as "+
					"settled invites the reader to treat the finding as resolved, and no "+
					"analysis that could not resolve a dispatch is entitled to that.", joined)
			}
		})
	}
}

// A refiner that named its blind spot has it rendered, because that is what
// lets a reader decide whether it matters to their code. "Cannot see interface
// dispatch" is actionable; "within what it could see" is only honest.
func TestANamedBlindSpotIsRendered(t *testing.T) {
	in := baseInputs()
	in.Ledger = evidence.Ledger{Claims: []evidence.Claim{
		refutation("a sanitizer cleared this value", map[string]string{
			"scope":  "the python taint engine, over this file",
			"limits": "interface dispatch, function values, reflection",
		}),
	}}
	joined := strings.Join(explain.Explain(in).Against, "\n")

	for _, want := range []string{
		"the python taint engine, over this file",
		"cannot see",
		"interface dispatch",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the rendered negative does not carry %q: %q", want, joined)
		}
	}
}

// A supporting claim is not qualified this way. The asymmetry is the point: an
// existential claim is settled by one witness however narrow the search was,
// and hedging it would train a reader to discount both.
func TestSupportIsNotQualifiedLikeARefutation(t *testing.T) {
	in := baseInputs()
	in.Ledger = evidence.Ledger{Claims: []evidence.Claim{{
		Kind: evidence.KindStatic, Statement: "the embedded checksum verifies",
		Subject: subject(), Provenance: evidence.Provenance{Source: "nox-scan"},
	}}}
	joined := strings.Join(explain.Explain(in).Supports, "\n")
	if strings.Contains(joined, "within what that analysis could see") {
		t.Errorf("a supporting claim was hedged like a negative: %q", joined)
	}
}
