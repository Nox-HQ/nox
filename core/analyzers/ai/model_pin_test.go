package ai

import (
	"testing"
)

// AI-019 is a precision fix, not a withdrawal: a real supply-chain proposition
// expressed badly.
//
// "Model loaded without hash verification" matched `from_pretrained(` and
// stopped at the paren, so it never saw the arguments. Its own comment conceded
// this and argued the absence was still "the signal" because "lines with
// revision= or sha256 are unlikely to match" — they match, being further along
// the same line changes nothing about a pattern that ends before them. A pinned
// load was reported exactly like an unpinned one.
//
// Of 99 model loads across the fourteen pinned repositories, zero carry a pin,
// so this changes no count. That is the measurement rather than an excuse: the
// rule was right about every one of them for a reason it could not give.

func aiRuleFired(t *testing.T, rule, body string) bool {
	t.Helper()
	got, err := NewAnalyzer().ScanFile("agent.py", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestAI019ReportsAnUnpinnedLoad(t *testing.T) {
	for _, line := range []string{
		`model = AutoModel.from_pretrained("bert-base-uncased")`,
		`m = load_model("weights")`,
		// A bare pipeline() at the start of a line. The guard excluding
		// `conn.pipeline()` is a character class, and a character class needs a
		// character — so this, the ordinary notebook idiom, matched nothing.
		`pipeline("sentiment-analysis")`,
	} {
		if !aiRuleFired(t, "AI-019", line+"\n") {
			t.Errorf("AI-019 did not report an unpinned model load: %s", line)
		}
	}
}

// The half the rule could not previously express. A project that does what the
// remediation asks must stop being told it has not.
func TestAI019AcceptsAPinnedLoad(t *testing.T) {
	for name, src := range map[string]string{
		"same line": `m = AutoModel.from_pretrained("bert-base-uncased", revision="a1b2c3d4e5f6")` + "\n",
		"multi line": "m = AutoModel.from_pretrained(\n" +
			"    \"bert-base-uncased\",\n" +
			"    revision=\"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\",\n" +
			")\n",
		"digest":   `m = load_model("weights", checksum="sha256:deadbeef")` + "\n",
		"no fetch": `m = AutoModel.from_pretrained("./local", local_files_only=True)` + "\n",
	} {
		if aiRuleFired(t, "AI-019", src) {
			t.Errorf("AI-019 reported a pinned load (%s) as unverified:\n%s", name, src)
		}
	}
}

// The exclusion must not swallow the method-call form the original guard
// existed to exclude, nor the ordinary unpinned load next to unrelated text.
func TestAI019StillExcludesAMethodCall(t *testing.T) {
	for _, line := range []string{
		`conn.pipeline()`,
		`r = redis.pipeline()`,
		`if has_pipeline():`,
	} {
		if aiRuleFired(t, "AI-019", line+"\n") {
			t.Errorf("AI-019 reported a method call named pipeline: %s", line)
		}
	}
}
