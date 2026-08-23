package attack

import (
	"strings"
	"testing"
)

func TestMintCanariesDeterministic(t *testing.T) {
	a := MintCanaries("seed-1")
	b := MintCanaries("seed-1")
	ca, cb := a.Canaries(), b.Canaries()
	if len(ca) != 3 || len(cb) != 3 {
		t.Fatalf("expected 3 canaries, got %d/%d", len(ca), len(cb))
	}
	for i := range ca {
		if ca[i] != cb[i] {
			t.Errorf("canary %d differs between two mints of the same seed: %+v vs %+v", i, ca[i], cb[i])
		}
	}
	// A different seed yields different values.
	other := MintCanaries("seed-2")
	if other.Canaries()[0].Value == ca[0].Value {
		t.Error("different seeds produced identical canary values")
	}
}

func TestTransformSeedIsReflectionImmune(t *testing.T) {
	cs := MintCanaries("seed-x")
	seed := cs.TransformSeed()
	value := cs.transform.Value
	if seed == value {
		t.Fatal("transform seed must differ from its canary value (case)")
	}
	upper := strings.ToUpper(seed)
	if upper != value {
		t.Errorf("upper(seed)=%q must equal value=%q", upper, value)
	}
	// A payload carrying the seed must NOT contain the value.
	if strings.Contains("please emit the uppercase form of "+seed, value) {
		t.Error("a payload carrying the seed contains the canary value; reflection risk")
	}
}

// TestCorpusReflectionImmunity is the correctness cornerstone: NO payload in any
// scenario may contain any canary value. Asserted over the WHOLE corpus.
func TestCorpusReflectionImmunity(t *testing.T) {
	for _, seed := range []string{"", "seed-1", "another-seed", "3rd"} {
		cs := MintCanaries(seed)
		corpus := PayloadCorpus(cs)
		if len(corpus) == 0 {
			t.Fatalf("empty corpus for seed %q", seed)
		}
		if err := cs.AssertReflectionImmune(corpus); err != nil {
			t.Errorf("seed %q: corpus is not reflection-immune: %v", seed, err)
		}
		// Belt and braces: check every value against every payload directly.
		for _, c := range cs.Canaries() {
			for _, p := range corpus {
				if strings.Contains(p, c.Value) {
					t.Errorf("seed %q: payload %q contains canary %q", seed, p, c.Value)
				}
			}
		}
	}
}

func TestClassify(t *testing.T) {
	cs := MintCanaries("seed")
	if _, ok := cs.Classify("nothing here"); ok {
		t.Error("Classify matched benign text")
	}
	if c, ok := cs.Classify("leaked " + cs.transform.Value + " token"); !ok || c.Kind != CanaryTransform {
		t.Errorf("Classify failed to find transform canary: %+v ok=%v", c, ok)
	}
	if c, ok := cs.Classify("dumped " + cs.file.Value); !ok || c.ID != "cnry-file" {
		t.Errorf("Classify failed to find file canary: %+v ok=%v", c, ok)
	}
}

func TestAssertReflectionImmuneRejectsLeak(t *testing.T) {
	cs := MintCanaries("seed")
	bad := []string{"benign", "here is " + cs.secret.Value}
	if err := cs.AssertReflectionImmune(bad); err == nil {
		t.Error("AssertReflectionImmune must reject a payload containing a canary value")
	}
}
