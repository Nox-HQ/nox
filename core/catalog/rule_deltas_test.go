package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ruleDelta struct {
	Rule           string `json:"rule"`
	Classification string `json:"classification"`
	PR             int    `json:"pr"`
	Reason         string `json:"reason"`
}

type deltaLedger struct {
	NoxRelease      string            `json:"nox_release"`
	Classifications map[string]string `json:"classifications"`
	Entries         []ruleDelta       `json:"entries"`
}

func loadLedger(t *testing.T) deltaLedger {
	t.Helper()
	path := filepath.Join("..", "..", "scripts", "rule-deltas.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var l deltaLedger
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return l
}

// TestRuleDeltaLedgerIsWellFormed checks here what rule-diff.sh checks in CI,
// so a malformed ledger fails in seconds rather than after a four-minute
// harness run that needs the network and ten clones.
//
// Shape matters as much as content. An entry with an empty reason, or naming a
// classification nobody defined, satisfies the harness's "is this rule
// accounted for?" lookup while explaining nothing — the failure the ledger
// exists to prevent, one indirection over.
func TestRuleDeltaLedgerIsWellFormed(t *testing.T) {
	l := loadLedger(t)

	if l.NoxRelease == "" {
		t.Error("ledger declares no nox_release; entries cannot be checked against the baseline they describe")
	}
	if len(l.Classifications) == 0 {
		t.Fatal("ledger defines no classifications; every classification would then validate vacuously")
	}

	seen := map[string]bool{}
	for _, e := range l.Entries {
		if e.Rule == "" {
			t.Errorf("entry %+v has no rule", e)
			continue
		}
		if seen[e.Rule] {
			t.Errorf("duplicate entry for %s; the second explanation is unreachable", e.Rule)
		}
		seen[e.Rule] = true

		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("%s has an empty reason; it satisfies the lookup and explains nothing", e.Rule)
		}
		if _, ok := l.Classifications[e.Classification]; !ok {
			t.Errorf("%s names classification %q, which is not defined in .classifications", e.Rule, e.Classification)
		}
		if e.PR <= 0 {
			t.Errorf("%s does not name the PR that made the change", e.Rule)
		}
	}
}

// TestRuleDeltaLedgerNamesRealRules is the typo guard.
//
// The harness matches observed drops against entries by rule ID. An ID
// belonging to no rule can never match a drop, so it is invisible to the
// unexplained-narrowing check and surfaces only as a STALE entry — with a
// message blaming a reverted change rather than the typo it is. Every entry
// must name a rule that still exists, or one a surviving rule retired.
//
// With one exception, and it is the case that showed the rule above had a hole.
// A `rule-removed` entry names an ID that is deliberately in neither set: the
// rule is gone and nothing absorbed it. It still matches a drop, because the
// harness diffs the BASELINE binary against the candidate and the baseline
// still has the rule — the drop is its count falling to zero. So the premise
// "belongs to no rule, therefore can never match a drop" is false precisely for
// a removal, and the classification is what distinguishes the two.
//
// The check is therefore run in both directions: a `rule-removed` entry must
// name an ID that is NOT live, because an entry claiming a removal of a rule
// still in the catalog is as wrong as a typo and fails the same way.
func TestRuleDeltaLedgerNamesRealRules(t *testing.T) {
	l := loadLedger(t)

	live := Catalog()
	retired := map[string]bool{}
	for _, rs := range allRuleSets() {
		for _, r := range rs.Rules() {
			for _, ret := range r.Retires {
				retired[ret.ID] = true
			}
		}
	}
	if len(live) == 0 || len(retired) == 0 {
		t.Fatal("no live or no retired rules found; the check below would pass vacuously")
	}

	for _, e := range l.Entries {
		if e.Rule == "" {
			continue
		}
		_, isLive := live[e.Rule]
		if e.Classification == "rule-removed" {
			if isLive {
				t.Errorf("%s is classified rule-removed but is still in the catalog; either "+
					"the removal did not land or the classification is wrong", e.Rule)
			}
			continue
		}
		if isLive || retired[e.Rule] {
			continue
		}
		t.Errorf("%s names no live rule and no retired ID; a drop can never match it, so the entry "+
			"explains nothing and will surface as a stale entry rather than as the typo it is. "+
			"If the rule was removed outright, classify the entry rule-removed.", e.Rule)
	}
}
