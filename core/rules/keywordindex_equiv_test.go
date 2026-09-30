package rules_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/rules"
)

// The index must agree with bytes.Contains on every built-in keyword over
// every fixture file, plus the corpus named by NOX_PREFIX_EQUIV_CORPUS.
func TestKeywordIndexMatchesContainsOnFixtures(t *testing.T) {
	var kws []string
	seen := map[string]bool{}
	for _, r := range catalog.Rules() {
		for _, k := range r.Keywords {
			if !seen[strings.ToLower(k)] {
				seen[strings.ToLower(k)] = true
				kws = append(kws, k)
			}
		}
	}
	roots := []string{"../../testdata", "../analyzers"}
	if extra := os.Getenv("NOX_PREFIX_EQUIV_CORPUS"); extra != "" {
		roots = append(roots, extra)
	}
	files := 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) > 4<<20 {
				return nil
			}
			files++
			lower := bytes.ToLower(b)
			for i, got := range rules.KeywordsPresent(kws, b) {
				if want := bytes.Contains(lower, []byte(strings.ToLower(kws[i]))); got != want {
					t.Fatalf("%s: keyword %q: index %v, Contains %v", p, kws[i], got, want)
				}
			}
			return nil
		})
	}
	t.Logf("%d keywords agree with bytes.Contains on %d files", len(kws), files)
	if files == 0 || len(kws) < 100 {
		t.Fatal("the equivalence was not exercised")
	}
}
