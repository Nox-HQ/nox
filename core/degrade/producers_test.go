package degrade_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryKindHasAProducer catches a declared-but-never-emitted degradation
// Kind.
//
// This is the guard for a real failure: degrade.Plugin and degrade.VulnData
// were declared, documented, and named in --fail-on-degraded's help text while
// nothing anywhere emitted them. A CI job listing a required security plugin,
// failing to install it, and running with that flag exited 0 with a clean
// report. Every unit test passed, because a Kind with no producer is invisible
// to tests of the code that would have produced it.
//
// It scans source rather than using a registry because the failure is exactly
// an absence — there is nothing to register when the call site was never
// written.
func TestEveryKindHasAProducer(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	kinds := declaredKinds(t, filepath.Join(root, "core", "degrade", "degrade.go"))
	if len(kinds) == 0 {
		t.Fatal("no Kind constants found; this test's parsing is stale")
	}

	emitted := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Only production code counts. A Kind emitted solely from a test is
		// still dead in the shipped binary.
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/degrade/") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for kind := range kinds {
			if strings.Contains(string(src), "degrade."+kind) {
				emitted[kind] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo: %v", err)
	}

	for kind := range kinds {
		if !emitted[kind] {
			t.Errorf("degrade.%s is declared but no production code emits it: "+
				"the condition it describes would pass silently, and --fail-on-degraded "+
				"would never fire for it. Wire it up or delete the constant.", kind)
		}
	}
}

// declaredKinds extracts the exported Kind constants from the degrade package.
func declaredKinds(t *testing.T, path string) map[string]bool {
	t.Helper()

	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	kinds := make(map[string]bool)
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		name, rest, found := strings.Cut(line, " Kind = ")
		if !found || rest == "" {
			continue
		}
		if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
			kinds[name] = true
		}
	}
	return kinds
}

func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate repo root")
	return ""
}
