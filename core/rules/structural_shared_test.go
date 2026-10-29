package rules_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/rules"
)

// TestSharedParseMatchesPerRuleParse is #736: ScanFile now parses a file once
// for all its structural absence rules instead of once per rule. Every such
// rule must decide exactly as it did with a parse of its own, on every fixture
// file in the repository.
func TestSharedParseMatchesPerRuleParse(t *testing.T) {
	var structural []*rules.Rule
	for _, r := range catalog.Rules() {
		if r.MatcherType == "absence" && len(r.AbsenceResourceTypes) > 0 {
			structural = append(structural, r)
		}
	}
	if len(structural) < 2 {
		t.Fatalf("%d structural absence rules; sharing a parse is not exercised", len(structural))
	}

	alone := rules.NewAbsenceMatcher()
	files, decided := 0, 0
	for _, root := range []string{"../../testdata", "../analyzers"} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".yaml" && ext != ".yml" && ext != ".json" {
				return nil
			}
			content, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			files++
			shared := rules.AbsenceMatchShared(structural, content)
			for i, r := range structural {
				want := alone.Match(content, r)
				if !reflect.DeepEqual(shared[i], want) {
					t.Fatalf("%s on %s: shared parse %+v, own parse %+v", r.ID, p, shared[i], want)
				}
				if len(want) > 0 {
					decided++
				}
			}
			return nil
		})
	}
	t.Logf("%d structural rules over %d YAML/JSON fixtures; %d rule/file pairs with results, all identical", len(structural), files, decided)
	if decided == 0 {
		t.Fatal("no rule reported anything; the equivalence was never exercised")
	}
}
