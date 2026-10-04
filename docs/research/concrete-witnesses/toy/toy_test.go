package toy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestBoundedEnumeration searches the partition the format description
// induces: each constraint in it (prefix, separator, body length, body
// alphabet, suffix) is varied at and around its boundary, and every
// combination is run through both functions.
func TestBoundedEnumeration(t *testing.T) {
	prefixes := []string{"acme_", "ACME_", "AcMe_", "acme-", "acm_", "acmee_", ""}
	lengths := []int{0, 1, 22, 23, 24, 25, 26, 27}
	// The character placed at position 0 of an otherwise valid body.
	firsts := []byte{'a', 'z', '2', '7', '1', '8', '0', '9', 'A', 'Z', '_', '.', '-'}
	suffixes := []string{"", ".v2", ".V2", ".v3", ".v", "v2", ".v2.v2"}

	var fp, fn []string
	n := 0
	for _, p := range prefixes {
		for _, l := range lengths {
			for _, f := range firsts {
				for _, s := range suffixes {
					body := ""
					if l > 0 {
						body = string(f) + strings.Repeat("q", l-1)
					}
					in := p + body + s
					n++
					v, r := Validate(in), Reference(in)
					switch {
					case v && !r:
						fp = append(fp, in)
					case r && !v:
						fn = append(fn, in)
					}
				}
			}
		}
	}
	t.Logf("enumerated %d inputs: %d accepted-but-invalid, %d valid-but-rejected", n, len(fp), len(fn))
	for _, w := range fp {
		t.Logf("  FP witness %q", w)
	}
	for _, w := range fn {
		t.Logf("  FN witness %q", w)
	}
	// The deliberate defect must be found, and nothing else.
	if len(fn) != 0 {
		t.Errorf("unexpected FN witnesses: %q", fn)
	}
	for _, w := range fp {
		if !strings.HasSuffix(w, ".v2") || len(w) != 5+25+3 {
			t.Errorf("FP witness outside the deliberate defect: %q", w)
		}
	}
	if len(fp) == 0 {
		t.Fatal("bounded enumeration did not find the deliberate defect")
	}
}

// TestPlausibleEdgeCaseIsNotAWitness: the uppercase prefix looks like a
// defect when Validate is read. Both functions accept it, because the format
// says the prefix is case-insensitive. A suspicion is not a witness.
func TestPlausibleEdgeCaseIsNotAWitness(t *testing.T) {
	in := "ACME_" + strings.Repeat("q", 24)
	if Validate(in) != Reference(in) {
		t.Fatalf("expected agreement on %q", in)
	}
}

// TestReplaySolverWitnesses replays every witness solve.py produced through
// the real functions. The solver's claim is only that the MODEL disagrees.
func TestReplaySolverWitnesses(t *testing.T) {
	b, err := os.ReadFile("witnesses.json")
	if err != nil {
		t.Skip("run: python3 solve.py > witnesses.json")
	}
	var doc struct {
		Witnesses []struct{ Model, Direction, Input string }
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, w := range doc.Witnesses {
		v, r := Validate(w.Input), Reference(w.Input)
		replayed := (w.Direction == "fp" && v && !r) || (w.Direction == "fn" && r && !v)
		t.Logf("%-10s %s %q -> Validate=%v Reference=%v replayed=%v", w.Model, w.Direction, w.Input, v, r, replayed)
		if w.Model == "faithful" && !replayed {
			t.Errorf("a faithful-model witness did not replay: %q", w.Input)
		}
	}
}
