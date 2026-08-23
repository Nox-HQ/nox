package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// scan.include parsed and was read by nothing: an operator narrowing a scan to
// a subtree got a full scan instead, with no indication. The direction is the
// safe one — more scanned, not less — but the policy in force was not the
// policy they wrote.
//
// Semantics chosen here, and pinned below:
//
//   - include is an allow-list of glob patterns. Non-empty means a file is
//     scanned only if it matches one.
//   - exclude still wins. It is an explicit "never scan this", and an operator
//     who writes both means the intersection, not a contradiction to resolve.
//   - directories are still descended. Pruning on a glob is where an include
//     implementation silently loses files (src/**/*.go tells you nothing about
//     whether src/a/b/ can contain a match), and losing files is exactly the
//     failure this setting was reported for. Excluding a subtree from the walk
//     is what scan.exclude is for.

// seedTree writes a small fixture and returns its root.
func seedTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{
		"src/app.go",
		"src/deep/util.go",
		"vendor/lib.go",
		"docs/readme.md",
		"main.go",
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte("package x\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// walkedPaths returns the slash-separated relative paths the walker yielded.
func walkedPaths(t *testing.T, w *Walker) map[string]bool {
	t.Helper()
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	out := map[string]bool{}
	for _, a := range arts {
		rel, err := filepath.Rel(w.Root, a.Path)
		if err != nil {
			rel = a.Path
		}
		out[filepath.ToSlash(rel)] = true
	}
	return out
}

// TestIncludePatternsNarrowTheScan is the behaviour scan.include always looked
// like it had.
func TestIncludePatternsNarrowTheScan(t *testing.T) {
	root := seedTree(t)

	all := walkedPaths(t, newTestWalker(root, nil, nil))
	if !all["src/app.go"] || !all["vendor/lib.go"] || !all["main.go"] {
		t.Fatalf("the control walk missed fixture files (%v); the comparisons below would be vacuous", all)
	}

	got := walkedPaths(t, newTestWalker(root, []string{"src/**"}, nil))
	if !got["src/app.go"] || !got["src/deep/util.go"] {
		t.Errorf("include src/** did not keep the src tree: %v", got)
	}
	for _, unwanted := range []string{"vendor/lib.go", "main.go", "docs/readme.md"} {
		if got[unwanted] {
			t.Errorf("include src/** still scanned %s; the setting did not narrow the scan", unwanted)
		}
	}
}

// TestExcludeWinsOverInclude pins the precedence. An operator who writes both
// means the intersection.
func TestExcludeWinsOverInclude(t *testing.T) {
	root := seedTree(t)
	got := walkedPaths(t, newTestWalker(root, []string{"src/**"}, []string{"src/deep/**"}))

	if !got["src/app.go"] {
		t.Error("the included file outside the exclusion was dropped")
	}
	if got["src/deep/util.go"] {
		t.Error("a path matching both include and exclude was scanned; exclude must win, because it " +
			"is an explicit \"never scan this\"")
	}
}

// TestNoIncludePatternsScansEverything guards the default. Treating an empty
// allow-list as "allow nothing" would turn every existing config into an empty
// scan that still reports success.
func TestNoIncludePatternsScansEverything(t *testing.T) {
	root := seedTree(t)
	got := walkedPaths(t, newTestWalker(root, nil, nil))
	for _, want := range []string{"src/app.go", "vendor/lib.go", "main.go"} {
		if !got[want] {
			t.Errorf("with no include patterns configured, %s was not scanned", want)
		}
	}
}

// newTestWalker builds a walker with gitignore off, so the fixture's fate is
// decided by the patterns under test and nothing else.
func newTestWalker(root string, include, exclude []string) *Walker {
	w := NewWalker(root)
	w.RespectGitignore = false
	w.IncludePatterns = include
	w.ExcludePatterns = exclude
	return w
}

// TestIncludePatternsComposeWithIncludePaths pins the claim the doc comment
// makes: IncludePatterns (config scan.include, glob-based) and IncludePaths
// (--changed-since, exact paths) are separate allow-lists, and a file must
// satisfy both.
//
// Getting this wrong in either direction is a coverage bug that reports
// success. If they were OR-ed, --changed-since would silently re-widen a
// narrowed scan; if one silently disabled the other, a narrowed scan would miss
// changed files it was asked to check.
func TestIncludePatternsComposeWithIncludePaths(t *testing.T) {
	root := seedTree(t)

	w := newTestWalker(root, []string{"src/**"}, nil)
	// --changed-since reports one file inside the include and one outside it.
	w.IncludePaths = map[string]bool{
		"src/app.go":    true,
		"vendor/lib.go": true,
	}
	got := walkedPaths(t, w)

	if !got["src/app.go"] {
		t.Error("a file satisfying both allow-lists was not scanned")
	}
	if got["vendor/lib.go"] {
		t.Error("a changed file outside scan.include was scanned; the two allow-lists were OR-ed, " +
			"so --changed-since silently re-widens a narrowed scan")
	}
	if got["src/deep/util.go"] {
		t.Error("a file inside scan.include but not among the changed paths was scanned; " +
			"--changed-since stopped narrowing")
	}
}
