package attack

import "testing"

// TestExtractFieldNeverPassesAnUnparsedBodyOffAsTheReply pins the distinction
// that keeps a misnamed --reply-field from reading as a defense. Observation.Reply
// is what the refusal oracle reads; handing it the serialized JSON of a body whose
// reply key we could not find let nox match refusal phrasing against arbitrary
// response text and report PREVENTED — blindness dressed as a guardrail.
func TestExtractFieldNeverPassesAnUnparsedBodyOffAsTheReply(t *testing.T) {
	tests := []struct {
		name, body, field, want string
	}{
		{"present", `{"reply":"hello"}`, "reply", "hello"},
		{"present under another key", `{"answer":"hello"}`, "answer", "hello"},
		{"non-string value is rendered raw", `{"reply":{"text":"hi"}}`, "reply", `{"text":"hi"}`},
		{"plain text has no field to name", `I cannot help with that.`, "reply", "I cannot help with that."},
		// The case that mattered: valid JSON, named field absent.
		{"absent from a JSON object", `{"answer":"I cannot help with that."}`, "reply", ""},
		{"absent from an empty JSON object", `{}`, "reply", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractField(tc.body, tc.field); got != tc.want {
				t.Errorf("extractField(%q, %q) = %q, want %q", tc.body, tc.field, got, tc.want)
			}
		})
	}
}

// TestRefusalOracleCannotFireOnAnUnreadableBody is the consequence stated as an
// invariant: a body nox could not read the reply out of must not produce an
// observed defense, whatever text the body happens to contain.
func TestRefusalOracleCannotFireOnAnUnreadableBody(t *testing.T) {
	obs := Observation{
		Body:  `{"answer":"I cannot help with that."}`,
		Reply: extractField(`{"answer":"I cannot help with that."}`, "reply"),
	}
	if v := RefusalOracle().Evaluate(obs); v.Violated {
		t.Errorf("the refusal oracle fired on a body whose reply field was never found (%q); "+
			"nox would report PREVENTED for a response it could not read", v.Detail)
	}
}
