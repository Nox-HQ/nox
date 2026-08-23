package secrets

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// SEC-163 shipped as "High-entropy hex string detected" with an entropy
// threshold of 4.5. Shannon entropy over a 16-symbol alphabet cannot exceed
// log2(16) = 4.0 bits per character, so the rule could never match a hex string
// — and, because every entropy rule shared one matcher that ran every
// tokenizer, it matched non-hex candidates instead and reported them under the
// hex description (#467).
//
// A rule that cannot fire is the silent-detector failure this repository keeps
// finding: it loads, it lists in `nox rules`, it runs on every file, and its
// absence of findings reads exactly like a clean scan.

// alphabetCeilings is the maximum Shannon entropy attainable by a candidate of
// each kind, in bits per character. A threshold at or above the ceiling
// disables the rule outright.
var alphabetCeilings = map[string]float64{
	// 16 hex digits. Case-insensitive input is folded by the tokenizer's
	// character class, but a mixed-case hex string draws on 22 symbols, so the
	// ceiling is stated for the case that actually bounds detection: a
	// single-case hex string, which is how keys are written.
	"hex": 4.0, // log2(16)
	// 64 base64 symbols plus padding.
	"base64": 6.0, // log2(64)
}

// TestEntropyRuleThresholdsAreReachable requires every kind-scoped entropy rule
// to ask for a threshold its alphabet can actually produce.
func TestEntropyRuleThresholdsAreReachable(t *testing.T) {
	var checked int
	for _, r := range builtinEntropyRules() {
		if r.MatcherType != "entropy" {
			continue
		}
		kinds := strings.Split(r.Metadata["candidate_kinds"], ",")
		threshold, ok := parseThreshold(r.Metadata["entropy_threshold"])
		if !ok {
			continue // the default threshold is exercised by the rules that use it
		}
		for _, k := range kinds {
			ceiling, known := alphabetCeilings[strings.TrimSpace(k)]
			if !known {
				continue // quoted/assignment candidates have no fixed alphabet
			}
			checked++
			if threshold >= ceiling {
				t.Errorf("%s is scoped to %s candidates and requires entropy >= %.2f, but a %s string "+
					"cannot exceed %.1f bits/char. The rule can never fire, and a rule that never fires "+
					"reports a clean scan indistinguishably from one that found nothing",
					r.ID, k, threshold, k, ceiling)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no kind-scoped entropy rule was checked; the guard is vacuous")
	}
}

// TestEntropyRulesDeclareTheKindTheyAreNamedFor keeps the rule text and the
// scoping honest with each other. A rule whose description says "hex" while it
// accepts every candidate kind is how #467 reported an identifier as a hex
// string.
func TestEntropyRulesDeclareTheKindTheyAreNamedFor(t *testing.T) {
	named := map[string]string{"hex": "hex", "base64": "base64"}
	var checked int
	for _, r := range builtinEntropyRules() {
		if r.MatcherType != "entropy" {
			continue
		}
		desc := strings.ToLower(r.Description)
		for word, kind := range named {
			if !strings.Contains(desc, word) {
				continue
			}
			checked++
			kinds := r.Metadata["candidate_kinds"]
			if kinds == "" {
				t.Errorf("%s is described as %q but declares no candidate_kinds, so it reports whatever "+
					"any tokenizer found — including candidates that are not %s at all",
					r.ID, r.Description, word)
				continue
			}
			if !strings.Contains(kinds, kind) {
				t.Errorf("%s is described as %q but is scoped to %q, which does not include %s",
					r.ID, r.Description, kinds, kind)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no entropy rule named for a specific encoding was found; the guard is vacuous")
	}
}

// parseThreshold reads an entropy_threshold metadata value.
func parseThreshold(v string) (float64, bool) {
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}
