package ai

import (
	"strings"
	"testing"
)

// AI-015 claims "LLM output rendered as raw HTML without escaping". Its pattern
// joined the two halves of that claim with `\s*`, and Go's `\s` matches a
// newline, so the halves could come from two unrelated lines:
//
//	# innerHTML
//	"""A minimal LLM agent that answers support questions over user data."""
//
//	match: 'innerHTML\n"""A minimal LLM'
//
// A comment naming innerHTML above a docstring mentioning an LLM is not raw
// rendering of anything. The corpus-wide metamorphic sweep had been failing on
// exactly this since 2026-09-07 -- adding that comment to a corpus seed made a
// finding appear, which is the definition of the violation it exists to catch.
//
// Rendering happens on one line, so the separator is `[ \t]*`.

func firedAI015(t *testing.T, name, body string) bool {
	t.Helper()

	got, err := NewAnalyzer().ScanFile(name, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i].RuleID == "AI-015" {
			return true
		}
	}
	return false
}

func TestAI015DoesNotJoinTwoLines(t *testing.T) {
	t.Parallel()

	// The exact seed mutation the sweep applies.
	body := "# innerHTML\n" +
		`"""A minimal LLM agent that answers support questions over user data."""` + "\n"
	if firedAI015(t, "agent.py", body) {
		t.Error("a comment naming innerHTML above a docstring mentioning an LLM was reported as " +
			"raw HTML rendering; the pattern is joining two unrelated lines again")
	}
}

func TestAI015StillCatchesRealRendering(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, body string }{
		{"app.js", "el.innerHTML = response.text;\n"},
		{"app.js", "node.innerHTML = completion;\n"},
		{"app.jsx", "<div dangerouslySetInnerHTML={{__html: completion}} />\n"},
		{"app.vue", `<div v-html="generated"></div>` + "\n"},
	} {
		if !firedAI015(t, tc.name, tc.body) {
			t.Errorf("AI-015 stopped reporting real unescaped rendering: %s",
				strings.TrimSpace(tc.body))
		}
	}
}
