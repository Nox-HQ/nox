package rules_test

import (
	"bytes"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/rules"
)

// The literal-prefix path must return exactly what FindAll returns, for every
// built-in regex rule, or it could drop a valid finding. This checks every
// rule with a plan against every fixture file in the repository -- they carry
// positive and negative examples for most rules -- plus the corpus named by
// NOX_PREFIX_EQUIV_CORPUS when set (run locally over the benchmark repos).
func TestPrefixPlanMatchesFindAll(t *testing.T) {
	type compiled struct {
		id       string
		re       *regexp.Regexp
		keywords [][]byte
	}
	var planned []compiled
	total := 0
	// Every file's literals come from one index over the built-in rules, as
	// ScanFile's do (literalindex.go).
	index := rules.NewLiteralIndex(catalog.Rules())
	for _, r := range catalog.Rules() {
		// An absence rule's anchor is located the same way (#736): its
		// positions decide where a missing property is reported.
		pattern := r.Pattern
		if r.MatcherType == "absence" {
			pattern = r.AbsenceAnchor
		} else if r.MatcherType != "regex" {
			continue
		}
		if pattern == "" {
			continue
		}
		total++
		if _, ok := rules.PrefixFindAll(nil, pattern, []byte("x"), false); !ok {
			continue
		}
		var kws [][]byte
		for _, k := range r.Keywords {
			kws = append(kws, []byte(strings.ToLower(k)))
		}
		planned = append(planned, compiled{r.ID, regexp.MustCompile(pattern), kws})
	}
	t.Logf("%d of %d regex patterns and absence anchors take the literal-prefix path", len(planned), total)
	if len(planned) == 0 {
		t.Fatal("no rule has a plan; the equivalence below checks nothing")
	}

	roots := []string{"../../testdata", "../analyzers"}
	if extra := os.Getenv("NOX_PREFIX_EQUIV_CORPUS"); extra != "" {
		roots = append(roots, extra)
	}
	files, matched := 0, 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 4<<20 {
				return nil
			}
			content, err := os.ReadFile(p)
			if err != nil || strings.IndexByte(string(content[:min(len(content), 8000)]), 0) >= 0 {
				return nil
			}
			// Under -race the detector multiplies the cost of the full-scan
			// reference by ~10 and finds nothing here: the property is about
			// matching, not concurrency. Check a sample so CI stays inside its
			// timeout; every other run checks every file.
			if raceEnabled && !inRaceSample(p, len(content)) {
				return nil
			}
			files++
			lower := bytes.ToLower(content)
			// One cache for the file, shared by every rule, as ScanFile
			// shares it: a literal one rule searched must answer the next.
			lits := rules.NewFileLiterals(index)
			for _, c := range planned {
				// Only where the engine would run the rule: its keyword
				// pre-filter passes. That is every case the fast path can
				// decide, and it keeps the test inside CI's time budget
				// under -race.
				if len(c.keywords) > 0 && !containsAny(lower, c.keywords) {
					continue
				}
				// The submatch form carries the whole-match pair too, so it
				// checks both shapes the matcher asks for.
				got, ok := rules.PrefixFindAll(lits, c.re.String(), content, true)
				if !ok {
					continue // a fold outlier in this file: the full scan runs
				}
				want := c.re.FindAllSubmatchIndex(content, -1)
				if len(want) == 0 && len(got) == 0 {
					continue
				}
				matched++
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s on %s: prefix path %v, FindAll %v", c.id, p, got, want)
				}
			}
			return nil
		})
	}
	t.Logf("checked %d files; %d rule/file pairs with matches, all identical", files, matched)
	if matched == 0 {
		t.Fatal("no rule matched any file; the equivalence was never exercised")
	}
}

// raceSampleMaxBytes bounds a file checked under -race. The largest files
// under the walked roots are rule tables of several hundred kilobytes; one of
// them costs more under the race detector than the rest of the sample.
const raceSampleMaxBytes = 64 << 10

// inRaceSample chooses the files checked under -race: a tenth of them, picked
// by each file's own path, and none above raceSampleMaxBytes.
//
// It used to take every tenth file in walk order. Which files that is depends
// on how many sort ahead of them, so adding a file anywhere moved the sample:
// eight new files in one pull request moved it onto secrets/rules.go (448 KB),
// and core/rules went from under three minutes to past CI's ten-minute
// timeout on macOS. Picked by path, a file is in or out whatever else exists.
func inRaceSample(path string, size int) bool {
	if size > raceSampleMaxBytes {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.ToSlash(path)))
	return h.Sum32()%10 == 0
}

func containsAny(content []byte, keywords [][]byte) bool {
	for _, k := range keywords {
		if bytes.Contains(content, k) {
			return true
		}
	}
	return false
}
