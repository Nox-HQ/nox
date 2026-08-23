package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// ---------------------------------------------------------------------------
// DefaultClassifier tests
// ---------------------------------------------------------------------------

func TestDefaultClassifier_Lockfiles(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	lockfiles := []string{
		"package-lock.json",
		"go.sum",
		"yarn.lock",
		"poetry.lock",
		"Gemfile.lock",
		"Cargo.lock",
		"pnpm-lock.yaml",
		"requirements.txt",
	}

	for _, name := range lockfiles {
		t.Run(name, func(t *testing.T) {
			got := c.Classify(name, nil)
			if got != Lockfile {
				t.Errorf("Classify(%q) = %q, want %q", name, got, Lockfile)
			}
		})
	}
}

func TestDefaultClassifier_Container(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	cases := []struct {
		path string
		want ArtifactType
	}{
		{"Dockerfile", Container},
		{"docker-compose.yml", Container},
		{"docker-compose.yaml", Container},
		{"build/app.dockerfile", Container},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := c.Classify(tc.path, nil)
			if got != tc.want {
				t.Errorf("Classify(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestDefaultClassifier_AIComponent(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	cases := []struct {
		path string
		want ArtifactType
	}{
		{"mcp.json", AIComponent},
		{"system.prompt", AIComponent},
		{"system.prompt.md", AIComponent},
		{"prompts/security.txt", AIComponent},
		// Recognised source under prompts/ or agents/ is Source, not AIComponent,
		// so taint/SAST/agentflow actually scan it. Non-source (.txt) stays AI.
		{"agents/scanner.go", Source},
		{"deep/nested/prompts/foo.txt", AIComponent},
		{"deep/nested/agents/bar.py", Source},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := c.Classify(tc.path, nil)
			if got != tc.want {
				t.Errorf("Classify(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestDefaultClassifier_Config(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	configs := []struct {
		path string
	}{
		{"config.yaml"},
		{"config.yml"},
		{"pyproject.toml"},
		{"settings.json"},
		{"app.ini"},
		{"nginx.cfg"},
		{"server.conf"},
		{".env"},
		{".env.local"},
		{".env.production"},
		{"main.tf"},
		{"vars.tfvars"},
	}

	for _, tc := range configs {
		t.Run(tc.path, func(t *testing.T) {
			got := c.Classify(tc.path, nil)
			if got != Config {
				t.Errorf("Classify(%q) = %q, want %q", tc.path, got, Config)
			}
		})
	}
}

func TestDefaultClassifier_Source(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	sources := []string{
		"main.go", "app.py", "index.js", "handler.ts", "gem.rb",
		"App.java", "lib.rs", "main.c", "engine.cpp", "header.h",
		"Program.cs", "build.sh",
		// Groovy source, a non-manifest Gradle script, and the extension-less
		// Jenkins pipeline file (classified as source by exact name).
		"Report.groovy", "settings.gradle", "Jenkinsfile", "ci/Jenkinsfile",
	}

	for _, name := range sources {
		t.Run(name, func(t *testing.T) {
			got := c.Classify(name, nil)
			if got != Source {
				t.Errorf("Classify(%q) = %q, want %q", name, got, Source)
			}
		})
	}
}

func TestDefaultClassifier_Unknown(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	unknowns := []string{
		"README.md",
		"logo.png",
		"archive.tar.gz",
		"binary.exe",
	}

	for _, name := range unknowns {
		t.Run(name, func(t *testing.T) {
			got := c.Classify(name, nil)
			if got != Unknown {
				t.Errorf("Classify(%q) = %q, want %q", name, got, Unknown)
			}
		})
	}
}

func TestDefaultClassifier_LockfileOverridesConfig(t *testing.T) {
	t.Parallel()
	c := &DefaultClassifier{}

	// package-lock.json has .json extension which would match Config,
	// but it should be classified as Lockfile due to priority.
	got := c.Classify("package-lock.json", nil)
	if got != Lockfile {
		t.Errorf("Classify(package-lock.json) = %q, want %q", got, Lockfile)
	}

	// pnpm-lock.yaml has .yaml extension but is a Lockfile.
	got = c.Classify("pnpm-lock.yaml", nil)
	if got != Lockfile {
		t.Errorf("Classify(pnpm-lock.yaml) = %q, want %q", got, Lockfile)
	}
}

// ---------------------------------------------------------------------------
// ClassifierRegistry tests
// ---------------------------------------------------------------------------

type stubClassifier struct {
	result ArtifactType
}

func (s *stubClassifier) Classify(_ string, _ os.FileInfo) ArtifactType {
	return s.result
}

func TestClassifierRegistry_FirstNonUnknownWins(t *testing.T) {
	t.Parallel()

	reg := NewClassifierRegistry()
	reg.Register(&stubClassifier{result: Unknown})
	reg.Register(&stubClassifier{result: Source})
	reg.Register(&stubClassifier{result: Config}) // should not be reached

	got := reg.Classify("test.go", nil)
	if got != Source {
		t.Errorf("Registry.Classify() = %q, want %q", got, Source)
	}
}

func TestClassifierRegistry_AllUnknown(t *testing.T) {
	t.Parallel()

	reg := NewClassifierRegistry()
	reg.Register(&stubClassifier{result: Unknown})

	got := reg.Classify("mystery.bin", nil)
	if got != Unknown {
		t.Errorf("Registry.Classify() = %q, want %q", got, Unknown)
	}
}

func TestClassifierRegistry_Empty(t *testing.T) {
	t.Parallel()

	reg := NewClassifierRegistry()
	got := reg.Classify("anything", nil)
	if got != Unknown {
		t.Errorf("empty registry should return Unknown, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Gitignore tests
// ---------------------------------------------------------------------------

func TestLoadGitignore_NoFile(t *testing.T) {
	// Isolate from global gitignore on the host system.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	patterns, err := LoadGitignore(dir)
	if err != nil {
		t.Fatalf("LoadGitignore returned unexpected error: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected no patterns, got %v", patterns)
	}
}

func TestLoadGitignore_ParsesPatterns(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	content := `# comment
node_modules/
*.log
!important.log

vendor/
`
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadGitignore(dir)
	if err != nil {
		t.Fatalf("LoadGitignore returned unexpected error: %v", err)
	}

	expected := []string{"node_modules/", "*.log", "!important.log", "vendor/"}
	if len(patterns) != len(expected) {
		t.Fatalf("expected %d patterns, got %d: %v", len(expected), len(patterns), patterns)
	}
	for i, p := range patterns {
		if p != expected[i] {
			t.Errorf("pattern[%d] = %q, want %q", i, p, expected[i])
		}
	}
}

func TestLoadGitignore_IncludesInfoExclude(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "exclude"), []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadGitignore(dir)
	if err != nil {
		t.Fatalf("LoadGitignore: %v", err)
	}
	found := false
	for _, p := range patterns {
		if p == "*.tmp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected *.tmp from .git/info/exclude, got %v", patterns)
	}
}

func TestLoadGitignore_IncludesGlobal(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(xdg, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "git", "ignore"), []byte(".DS_Store\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadGitignore(t.TempDir())
	if err != nil {
		t.Fatalf("LoadGitignore: %v", err)
	}
	found := false
	for _, p := range patterns {
		if p == ".DS_Store" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected .DS_Store from XDG global, got %v", patterns)
	}
}

// Regression for #82: when the scan target is a subdirectory, the
// walker should still honor the project-root .gitignore. Previously
// LoadGitignore only consulted the target's own .gitignore, so
// `nox scan apps/api` would walk apps/api/node_modules even though
// node_modules was ignored at the repo root.
func TestLoadGitignore_TraversesAncestorsUpToRepoRoot(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, ".gitignore"), []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	apps := filepath.Join(repoRoot, "apps", "api")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadGitignore(apps)
	if err != nil {
		t.Fatalf("LoadGitignore: %v", err)
	}
	found := false
	for _, p := range patterns {
		if p == "node_modules/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected repo-root node_modules/ pattern to flow into a sub-target scan; got %v", patterns)
	}
}

// Regression for #82: scanning a subdirectory of a repo must actually
// skip ignored directories during traversal, not just load the
// patterns. End-to-end check that the walker stops descending into
// node_modules when the repo-root .gitignore lists it.
func TestWalker_RespectsRepoRootGitignoreFromSubTarget(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, ".gitignore"), []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// apps/api/node_modules/should-skip.js should NOT be scanned.
	target := filepath.Join(repoRoot, "apps", "api")
	if err := os.MkdirAll(filepath.Join(target, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "node_modules", "should-skip.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// apps/api/src/keep.go SHOULD be scanned.
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "src", "keep.go"), []byte("package x"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(target)
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	have := map[string]bool{}
	for _, a := range arts {
		have[a.Path] = true
	}
	if have["node_modules/should-skip.js"] {
		t.Error("repo-root gitignore should have caused node_modules/should-skip.js to be skipped from a sub-target scan")
	}
	if !have["src/keep.go"] {
		t.Error("src/keep.go should still be walked")
	}
}

// Regression for #140: in a linked git worktree, `.git` is a gitdir-pointer
// *file*, not a directory. Joining `.git/info/exclude` onto it yielded an
// ENOTDIR error that LoadGitignore propagated — discarding every pattern it
// had already collected from `.gitignore` (a bare `return nil, err`). The
// walker then saw zero ignore patterns and scanned the whole tree, so a scan
// run from a worktree found strictly more than the same scan from the real
// checkout. LoadGitignore must resolve info/exclude via the worktree's
// commondir (git shares it across worktrees) and still return the
// `.gitignore` patterns.
func TestLoadGitignore_WorktreeGitFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	// The real checkout: `.git` is a directory with info/exclude.
	main := t.TempDir()
	if err := os.MkdirAll(filepath.Join(main, ".git", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, ".git", "info", "exclude"), []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A linked worktree: `.git` is a file pointing at the per-worktree
	// gitdir, which carries a `commondir` back to the main `.git`.
	wt := t.TempDir()
	gitDir := filepath.Join(main, ".git", "worktrees", "wt")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The worktree's checked-out `.gitignore` (a tracked file).
	if err := os.WriteFile(filepath.Join(wt, ".gitignore"), []byte("mobile/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadGitignore(wt)
	if err != nil {
		t.Fatalf("LoadGitignore from worktree: %v", err)
	}
	var haveMobile, haveTmp bool
	for _, p := range patterns {
		switch p {
		case "mobile/":
			haveMobile = true
		case "*.tmp":
			haveTmp = true
		}
	}
	if !haveMobile {
		t.Errorf("worktree scan dropped the .gitignore `mobile/` pattern (got %v) — a worktree would scan more than the real checkout", patterns)
	}
	if !haveTmp {
		t.Errorf("worktree scan did not resolve info/exclude via commondir (got %v)", patterns)
	}
}

// A config `scan.exclude` (ExcludePatterns) is a HARD exclude: it must win even
// over a tracked file, unlike a .gitignore pattern. Regression for the #142
// tracked-override resurrecting excluded-but-tracked files (e.g. nox's own
// rule-definition files, which are tracked and listed in scan.exclude but were
// re-scanned under --changed-since, failing the PR gate).
func TestWalker_ExcludePatternsWinOverTracked(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "rules.go"), "package x // excluded despite tracked")
	mustWrite(t, filepath.Join(root, "app.go"), "package x")

	w := NewWalker(root)
	w.ExcludePatterns = []string{"rules.go"}
	// Both files are tracked — the exclude must still drop rules.go.
	w.TrackedPaths = map[string]bool{"rules.go": true, "app.go": true}

	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	have := map[string]bool{}
	for _, a := range arts {
		have[a.Path] = true
	}
	if have["rules.go"] {
		t.Error("scan.exclude must skip a tracked file (hard exclude wins over the tracked-file override)")
	}
	if !have["app.go"] {
		t.Error("app.go should still be scanned")
	}
}

// Regression for #142: git never ignores a *tracked* file, even when a
// .gitignore pattern matches it. A repo that .gitignores a directory but
// commits sources into it (pet-medical: `mobile/` ignored, ~80 tracked
// files under it) must still have those tracked files scanned. The walker
// honors TrackedPaths: a tracked file under an ignored dir is scanned, the
// ignored dir is descended into to reach it, but a genuinely-ignored
// (untracked) sibling stays skipped and an ignored dir with no tracked
// descendant is still pruned.
func TestWalker_ScansTrackedFilesUnderIgnoredDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("mobile/\nbuild/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mobile/ is ignored but two files under it are tracked; a third is not.
	mustWrite(t, filepath.Join(root, "mobile", "app.go"), "package m")         // tracked
	mustWrite(t, filepath.Join(root, "mobile", "sub", "util.go"), "package s") // tracked (nested)
	mustWrite(t, filepath.Join(root, "mobile", "generated.go"), "package m")   // ignored + untracked
	// build/ is ignored and holds no tracked files → must stay pruned.
	mustWrite(t, filepath.Join(root, "build", "out.go"), "package b")
	// a normal tracked file outside any ignore.
	mustWrite(t, filepath.Join(root, "src", "main.go"), "package main")

	w := NewWalker(root)
	w.TrackedPaths = map[string]bool{
		"mobile/app.go":      true,
		"mobile/sub/util.go": true,
		"src/main.go":        true,
	}
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	have := map[string]bool{}
	for _, a := range arts {
		have[a.Path] = true
	}

	for _, want := range []string{"mobile/app.go", "mobile/sub/util.go", "src/main.go"} {
		if !have[want] {
			t.Errorf("tracked file %q under an ignored dir should be scanned; got %v", want, keys(have))
		}
	}
	if have["mobile/generated.go"] {
		t.Error("mobile/generated.go is ignored and untracked — it should not be scanned")
	}
	if have["build/out.go"] {
		t.Error("build/ is ignored with no tracked files — it should stay pruned")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Regression for #83: --changed-since must short-circuit the file
// walk, not just filter the artifact list afterwards. The walker now
// accepts an IncludePaths allow-list and skips directories that don't
// contain any included path.
func TestWalker_IncludePathsRestrictsTraversal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	// Three files, two of which the caller will mark as "changed".
	mustWrite := func(rel, body string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("src/changed.go", "package x")
	mustWrite("src/unchanged.go", "package x")
	mustWrite("other/skip.go", "package x")

	w := NewWalker(root)
	w.IncludePaths = map[string]bool{
		"src/changed.go": true,
	}
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(arts) != 1 || arts[0].Path != "src/changed.go" {
		t.Errorf("expected only src/changed.go in artifacts; got %v", arts)
	}
}

func TestWalker_RespectsNestedGitignore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Nested .gitignore in sub/ ignores *.log within sub.
	if err := os.WriteFile(filepath.Join(sub, ".gitignore"), []byte("*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "skip.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Root-level .log is unaffected by the nested gitignore.
	if err := os.WriteFile(filepath.Join(root, "root.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	have := map[string]bool{}
	for _, a := range arts {
		have[a.Path] = true
	}
	if have["sub/skip.log"] {
		t.Error("nested gitignore should have skipped sub/skip.log")
	}
	if !have["sub/keep.txt"] {
		t.Error("nested gitignore should not have skipped sub/keep.txt")
	}
	if !have["root.log"] {
		t.Error("nested gitignore must not affect root files")
	}
}

func TestWalker_NoRespectGitignore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "root.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	w.RespectGitignore = false
	arts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	have := map[string]bool{}
	for _, a := range arts {
		have[a.Path] = true
	}
	if !have["root.log"] {
		t.Error("RespectGitignore=false should have included root.log")
	}
}

func TestIsIgnored_ExactName(t *testing.T) {
	t.Parallel()

	patterns := []string{"secret.key"}
	if !IsIgnored("secret.key", patterns) {
		t.Error("expected secret.key to be ignored")
	}
	if !IsIgnored("sub/secret.key", patterns) {
		t.Error("expected sub/secret.key to be ignored (pattern matches any component)")
	}
	if IsIgnored("other.key", patterns) {
		t.Error("expected other.key to NOT be ignored")
	}
}

func TestIsIgnored_Wildcard(t *testing.T) {
	t.Parallel()

	patterns := []string{"*.log"}
	if !IsIgnored("error.log", patterns) {
		t.Error("expected error.log to be ignored")
	}
	if !IsIgnored("sub/debug.log", patterns) {
		t.Error("expected sub/debug.log to be ignored")
	}
	if IsIgnored("log.txt", patterns) {
		t.Error("expected log.txt to NOT be ignored")
	}
}

func TestIsIgnored_DirectoryPattern(t *testing.T) {
	t.Parallel()

	patterns := []string{"vendor/"}
	if !IsIgnored("vendor/lib.go", patterns) {
		t.Error("expected vendor/lib.go to be ignored")
	}
	// A directory pattern should not match a file with the same name.
	if IsIgnored("vendor", patterns) {
		t.Error("expected bare 'vendor' (as file) to NOT be ignored by dir pattern")
	}
}

func TestIsIgnored_Negation(t *testing.T) {
	t.Parallel()

	patterns := []string{"*.log", "!important.log"}
	if !IsIgnored("error.log", patterns) {
		t.Error("expected error.log to be ignored")
	}
	if IsIgnored("important.log", patterns) {
		t.Error("expected important.log to NOT be ignored (negated)")
	}
}

func TestIsIgnored_GitAlwaysIgnored(t *testing.T) {
	t.Parallel()

	// .git is always ignored even with no patterns.
	if !IsIgnored(".git/config", nil) {
		t.Error("expected .git/config to always be ignored")
	}
	if !IsIgnored(".git", nil) {
		t.Error("expected .git to always be ignored")
	}
}

// ---------------------------------------------------------------------------
// Walker integration tests
// ---------------------------------------------------------------------------

// createTestTree creates a temporary directory with a realistic project layout
// and returns the root path. Caller should use t.TempDir() to manage cleanup.
func createTestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	files := map[string]string{
		"main.go":                   "package main",
		"go.sum":                    "checksum data",
		"Dockerfile":                "FROM golang",
		"config.yaml":               "key: value",
		".env":                      "SECRET=abc",
		"src/handler.ts":            "export {}",
		"src/utils.py":              "pass",
		"prompts/security.txt":      "prompt text",
		"agents/scanner.go":         "package agents",
		"vendor/lib/dep.go":         "package dep",
		"node_modules/pkg/index.js": "module.exports={}",
		".git/HEAD":                 "ref: refs/heads/main",
		".git/config":               "[core]",
		"dist/bundle.js":            "compiled",
		"README.md":                 "# Project",
		"build/app.dockerfile":      "FROM alpine",
		"mcp.json":                  "{}",
		"system.prompt":             "you are helpful",
		"docs/guide.prompt.md":      "# Guide",
		"infra/main.tf":             "resource {}",
		"requirements.txt":          "flask==2.0",
	}

	for relPath, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func TestWalker_SkipsGitDirectory(t *testing.T) {
	t.Parallel()

	root := createTestTree(t)
	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	for _, a := range artifacts {
		if filepath.Base(a.Path) == "HEAD" && a.Type == Unknown {
			// .git/HEAD should have been skipped
			t.Errorf("Walker should skip .git/ directory but found: %s", a.Path)
		}
		if a.Path == ".git/config" || a.Path == ".git/HEAD" {
			t.Errorf("Walker should skip .git/ directory but found: %s", a.Path)
		}
	}
}

func TestWalker_ClassifiesFileTypes(t *testing.T) {
	t.Parallel()

	root := createTestTree(t)
	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	// Build a map for easy lookup.
	byPath := make(map[string]ArtifactType)
	for _, a := range artifacts {
		byPath[a.Path] = a.Type
	}

	expectations := map[string]ArtifactType{
		"main.go":              Source,
		"go.sum":               Lockfile,
		"Dockerfile":           Container,
		"config.yaml":          Config,
		".env":                 Config,
		"src/handler.ts":       Source,
		"src/utils.py":         Source,
		"prompts/security.txt": AIComponent,
		"agents/scanner.go":    Source, // source under agents/ must reach taint/SAST
		"README.md":            Unknown,
		"build/app.dockerfile": Container,
		"mcp.json":             AIComponent,
		"system.prompt":        AIComponent,
		"docs/guide.prompt.md": AIComponent,
		"infra/main.tf":        Config,
		"requirements.txt":     Lockfile,
	}

	for path, want := range expectations {
		got, ok := byPath[path]
		if !ok {
			t.Errorf("expected artifact %q not found in results", path)
			continue
		}
		if got != want {
			t.Errorf("artifact %q: got type %q, want %q", path, got, want)
		}
	}
}

func TestWalker_ArtifactsSortedByPath(t *testing.T) {
	t.Parallel()

	root := createTestTree(t)
	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	for i := 1; i < len(artifacts); i++ {
		if artifacts[i].Path < artifacts[i-1].Path {
			t.Errorf("artifacts not sorted: %q should come before %q",
				artifacts[i].Path, artifacts[i-1].Path)
		}
	}
}

func TestWalker_GitignoreFiltering(t *testing.T) {
	t.Parallel()

	root := createTestTree(t)

	// Write a .gitignore that excludes vendor/ and node_modules/ and dist/.
	gitignore := `vendor/
node_modules/
dist/
`
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(gitignore), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	for _, a := range artifacts {
		switch a.Path {
		case "vendor/lib/dep.go":
			t.Errorf("vendor/ should be ignored but found: %s", a.Path)
		case "node_modules/pkg/index.js":
			t.Errorf("node_modules/ should be ignored but found: %s", a.Path)
		case "dist/bundle.js":
			t.Errorf("dist/ should be ignored but found: %s", a.Path)
		}
	}

	// Verify non-ignored files are still present.
	byPath := make(map[string]bool)
	for _, a := range artifacts {
		byPath[a.Path] = true
	}
	for _, expected := range []string{"main.go", "Dockerfile", "src/handler.ts"} {
		if !byPath[expected] {
			t.Errorf("expected non-ignored file %q to be present", expected)
		}
	}
}

func TestWalker_ArtifactFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := "package main\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	if len(artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(artifacts))
	}

	a := artifacts[0]
	if a.Path != "main.go" {
		t.Errorf("Path = %q, want %q", a.Path, "main.go")
	}
	if a.AbsPath == "" {
		t.Error("AbsPath should not be empty")
	}
	if !filepath.IsAbs(a.AbsPath) {
		t.Errorf("AbsPath %q should be absolute", a.AbsPath)
	}
	if a.Type != Source {
		t.Errorf("Type = %q, want %q", a.Type, Source)
	}
	if a.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", a.Size, len(content))
	}
}

func TestWalker_EmptyDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}
	if len(artifacts) != 0 {
		t.Errorf("expected 0 artifacts in empty dir, got %d", len(artifacts))
	}
}

func TestWalker_NonexistentRoot(t *testing.T) {
	t.Parallel()

	w := NewWalker("/nonexistent/path/that/should/not/exist")
	_, err := w.Walk()
	if err == nil {
		t.Error("Walk() should return error for nonexistent root")
	}
}

func TestIsIgnored_RootAnchored(t *testing.T) {
	t.Parallel()

	patterns := []string{"/nox", "/build"}

	// Root-anchored pattern should match file at root.
	if !IsIgnored("nox", patterns) {
		t.Error("expected 'nox' to be ignored by root-anchored /nox pattern")
	}
	if !IsIgnored("build", patterns) {
		t.Error("expected 'build' to be ignored by root-anchored /build pattern")
	}

	// Should NOT match in subdirectories.
	if IsIgnored("src/nox", patterns) {
		t.Error("expected 'src/nox' to NOT be ignored by root-anchored /nox pattern")
	}
	if IsIgnored("out/build", patterns) {
		t.Error("expected 'out/build' to NOT be ignored by root-anchored /build pattern")
	}
}

func TestWalker_GitignoreRootAnchored(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create a binary-like file at root and a file in a subdirectory.
	for _, f := range []string{"nox", "src/nox"} {
		abs := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("binary content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// .gitignore with root-anchored pattern.
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("/nox\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	byPath := make(map[string]bool)
	for _, a := range artifacts {
		byPath[a.Path] = true
	}

	if byPath["nox"] {
		t.Error("root 'nox' should be ignored by /nox pattern")
	}
	if !byPath["src/nox"] {
		t.Error("src/nox should NOT be ignored by root-anchored /nox pattern")
	}
}

func TestWalker_GitignoreWithNegation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create files.
	for _, f := range []string{"error.log", "important.log", "debug.log"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("log data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// .gitignore that ignores all .log but keeps important.log.
	gitignore := "*.log\n!important.log\n"
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(gitignore), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWalker(root)
	artifacts, err := w.Walk()
	if err != nil {
		t.Fatalf("Walk() returned unexpected error: %v", err)
	}

	byPath := make(map[string]bool)
	for _, a := range artifacts {
		byPath[a.Path] = true
	}

	// .gitignore itself should be present (it is a regular file, Unknown type).
	if !byPath[".gitignore"] {
		t.Error(".gitignore should be present")
	}

	if byPath["error.log"] {
		t.Error("error.log should be ignored")
	}
	if byPath["debug.log"] {
		t.Error("debug.log should be ignored")
	}
	if !byPath["important.log"] {
		t.Error("important.log should NOT be ignored (negation pattern)")
	}
}

// ---------------------------------------------------------------------------
// Gitignore edge cases: non-ENOENT errors, root-anchored dir patterns
// ---------------------------------------------------------------------------

func TestLoadGitignore_DirectoryInsteadOfFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Create .gitignore as a directory — Open should fail with a non-ENOENT
	// error (on most systems, read of a directory fails).
	gitignorePath := filepath.Join(dir, ".gitignore")
	if err := os.Mkdir(gitignorePath, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := LoadGitignore(dir)
	if err == nil {
		t.Fatal("expected error when .gitignore is a directory, got nil")
	}
}

func TestMatchPattern_RootAnchoredDirPattern(t *testing.T) {
	t.Parallel()

	// Pattern "/build/" should match "build/output.js" (root-anchored dir).
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{"root-anchored dir prefix match", "build/output.js", "/build/", true},
		{"root-anchored dir exact match", "build", "/build/", true},
		{"root-anchored dir no match nested", "src/build/output.js", "/build/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchPattern_SlashContainingDirOnly(t *testing.T) {
	t.Parallel()

	// Pattern "sub/vendor/" (contains slash, trailing /) should match
	// paths like "sub/vendor/lib.go" but not "other/sub/vendor/lib.go".
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{"prefix match", "sub/vendor/lib.go", "sub/vendor/", true},
		{"exact match", "sub/vendor", "sub/vendor/", true},
		{"no match different root", "other/sub/vendor/lib.go", "sub/vendor/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

// Every extension the lexer can analyse must also be classified as Source here,
// or files nox fully understands get skipped by source-gated rules. This guard
// fails if sourceExtensions falls behind lexctx again — the exact drift that
// left .kts/.pyi/.gemspec/etc unscanned.
func TestSourceExtensionsCoverTheLexer(t *testing.T) {
	for _, ext := range lexctx.SourceExtensions() {
		if !sourceExtensions[ext] {
			t.Errorf("lexer supports %q but discovery does not classify it as Source — "+
				"add it to sourceExtensions or source-gated rules will skip it", ext)
		}
	}
}
