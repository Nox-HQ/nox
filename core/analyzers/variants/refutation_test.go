package variants

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// A signature's counter-pattern is a refutation and is recorded as one.
//
// VARIANT-002 matches `yaml.load(...)` — CVE-2020-1747's shape — and excludes
// the form that carries a safe Loader. That exclusion is the analyzer's only
// refinement, and stage accounting reported VARIANT as refuting nothing: true
// of the ledger, false of the analyzer.
//
// It is asserted here rather than from a corpus because no committed corpus
// exercises it. A refinement whose recording is only claimed is exactly what
// this milestone is about.
func TestAnExcludedMatchIsRecordedAsRefuted(t *testing.T) {
	a := NewAnalyzer()
	if a.LoadErr() != nil {
		t.Fatalf("signatures did not load: %v", a.LoadErr())
	}
	store := reasoning.New()
	a.RecordReasoningTo(store)

	// The vulnerable shape and the fixed shape, one line each.
	src := "import yaml\n" +
		"bad = yaml.load(stream)\n" +
		"good = yaml.load(stream, Loader=yaml.SafeLoader)\n"

	fs := findings.NewFindingSet()
	a.scanFile(fs, "app.py", []byte(src))

	var reported int
	for _, f := range fs.Findings() {
		if f.RuleID == "VARIANT-002" {
			reported++
		}
	}
	if reported == 0 {
		t.Fatal("the vulnerable line produced no VARIANT-002; this test asserts nothing")
	}

	var refutations int
	for _, s := range store.Subjects() {
		for _, c := range store.About(s).Claims {
			if !c.Refutes() {
				continue
			}
			refutations++
			if !strings.Contains(c.Statement, "exclusion pattern") {
				t.Errorf("refutation does not say what removed the match: %q", c.Statement)
			}
		}
	}
	if refutations == 0 {
		t.Error("the safe form was excluded and nothing recorded why. A counter-pattern " +
			"that drops the wrong match then looks exactly like one that had nothing " +
			"to drop — both report only the vulnerable line.")
	}
}

// A nil store is safe, so the recording call needs no guard at the drop site.
func TestNilStoreIsSafeForVariants(t *testing.T) {
	a := NewAnalyzer()
	fs := findings.NewFindingSet()
	a.scanFile(fs, "app.py", []byte("bad = yaml.load(stream)\n"))
}
