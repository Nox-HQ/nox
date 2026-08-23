package core

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// scan.exclude was already enforced host-side on plugin findings, on the stated
// principle that "a plugin is third-party code and cannot be relied on to
// honour an exclusion it is merely told about". scan.include arrived later and
// was wired only into the walker, so it narrowed core findings and left plugin
// findings alone.
//
// That makes one setting mean two different things depending on which analyzer
// happened to find the issue: an operator who narrows a scan to src/** still
// gets plugin findings from vendor/. The point of enforcing scope host-side is
// that "in scope" means the same thing for every analyzer.

// pluginFindingAt builds a plugin finding at a repo-relative path.
func pluginFindingAt(root, rel string) findings.Finding {
	return findings.Finding{
		RuleID:   "SAST-001",
		Message:  "hardcoded credential",
		Location: findings.Location{FilePath: filepath.Join(root, filepath.FromSlash(rel)), StartLine: 3},
	}
}

// keptPaths returns the slash-separated paths that survived filtering.
func keptPaths(kept []findings.Finding) []string {
	out := make([]string, 0, len(kept))
	for _, f := range kept {
		out = append(out, filepath.ToSlash(f.Location.FilePath))
	}
	return out
}

func TestPluginFindingsHonourScanInclude(t *testing.T) {
	root := t.TempDir()
	in := []findings.Finding{
		pluginFindingAt(root, "src/app.go"),
		pluginFindingAt(root, "vendor/lib.go"),
		pluginFindingAt(root, "docs/readme.md"),
	}

	t.Run("no include keeps everything", func(t *testing.T) {
		kept, dropped := filterPluginFindingsByScope(in, root, nil, nil)
		if len(kept) != 3 || dropped != 0 {
			t.Fatalf("kept %v (dropped %d); with no scope configured every finding must survive, "+
				"or existing scans silently lose plugin coverage", keptPaths(kept), dropped)
		}
	})

	t.Run("include narrows plugin findings the same way it narrows core ones", func(t *testing.T) {
		kept, dropped := filterPluginFindingsByScope(in, root, nil, []string{"src/**"})
		got := keptPaths(kept)
		if len(got) != 1 || got[0] != "src/app.go" {
			t.Errorf("kept %v, want only src/app.go — scan.include narrowed the walker but not the "+
				"plugin findings, so one setting means two things", got)
		}
		if dropped != 2 {
			t.Errorf("dropped %d, want 2", dropped)
		}
	})

	t.Run("exclude still wins over include", func(t *testing.T) {
		kept, _ := filterPluginFindingsByScope(in, root,
			[]string{"src/**"}, []string{"src/**"})
		if len(kept) != 0 {
			t.Errorf("kept %v; a path matching both must be excluded, as it is for core findings",
				keptPaths(kept))
		}
	})

	t.Run("a repository-scoped finding is never scoped out", func(t *testing.T) {
		repoScoped := []findings.Finding{{
			RuleID:   "DEPCONF-002",
			Message:  "no private registry config for this ecosystem",
			Location: findings.Location{FilePath: root},
		}}
		kept, _ := filterPluginFindingsByScope(repoScoped, root, nil, []string{"src/**"})
		if len(kept) != 1 {
			t.Fatal("a finding about the repository itself was dropped by an include pattern; it has " +
				"no path for a pattern to match, so narrowing by path must not silence it")
		}
		if kept[0].Location.FilePath != "" {
			t.Errorf("repository-scoped path is %q, want empty", kept[0].Location.FilePath)
		}
	})
}
