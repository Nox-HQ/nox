package authz

import (
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// moduleCandidatesOracle is the scan moduleSuffixes replaced: every file, in
// order, whose stem is rel or ends in "/"+rel.
func moduleCandidatesOracle(order []string, rel string) []string {
	var out []string
	for _, p := range order {
		stem := moduleStem(p)
		if stem == rel || strings.HasSuffix(stem, "/"+rel) {
			out = append(out, p)
		}
	}
	return out
}

func assertModuleIndex(t *testing.T, order, rels []string) {
	t.Helper()
	by := moduleSuffixes(order)
	for _, rel := range rels {
		if got, want := by[rel], moduleCandidatesOracle(order, rel); !slices.Equal(got, want) {
			t.Fatalf("rel %q: index %v, scan %v", rel, got, want)
		}
	}
}

// TestModuleSuffixesMatchTheScan draws trees with repeated directory names,
// packages beside modules of the same name (a/b.py, a/b/__init__.py), a
// top-level __init__.py, and asks for every suffix and for near misses.
func TestModuleSuffixesMatchTheScan(t *testing.T) {
	names := []string{"a", "b", "ab", "users", "api"}
	r := rand.New(rand.NewSource(966))
	for range 2000 {
		var order []string
		for range 1 + r.Intn(12) {
			var parts []string
			for range r.Intn(4) {
				parts = append(parts, names[r.Intn(len(names))])
			}
			switch r.Intn(3) {
			case 0:
				parts = append(parts, "__init__.py")
			default:
				parts = append(parts, names[r.Intn(len(names))]+".py")
			}
			order = append(order, strings.Join(parts, "/"))
		}
		var rels []string
		for range 20 {
			var parts []string
			for range 1 + r.Intn(3) {
				parts = append(parts, names[r.Intn(len(names))])
			}
			rels = append(rels, strings.Join(parts, "/"))
		}
		rels = append(rels, "__init__", "b/", "/b", "a.py")
		assertModuleIndex(t, order, rels)
	}
}

// TestModuleSuffixesOnARealTree asks for every module of the repository's
// Python fixtures, and of NOX_PY_MODULE_CORPUS when set (crewAI).
func TestModuleSuffixesOnARealTree(t *testing.T) {
	roots := []string{"../../../testdata"}
	if c := os.Getenv("NOX_PY_MODULE_CORPUS"); c != "" {
		roots = append(roots, c)
	}
	for _, root := range roots {
		var order []string
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() && strings.HasSuffix(p, ".py") {
				rel, _ := filepath.Rel(root, p)
				order = append(order, filepath.ToSlash(rel))
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		var rels []string
		for _, p := range order {
			stem := moduleStem(p)
			rels = append(rels, stem, stem+"x")
			for i := range len(stem) {
				if stem[i] == '/' {
					rels = append(rels, stem[i+1:])
				}
			}
		}
		assertModuleIndex(t, order, rels)
		t.Logf("%s: %d files, %d module paths", root, len(order), len(rels))
	}
}
