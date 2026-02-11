package discovery

import (
	"os"
	"path/filepath"
	"testing"
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
		{"agents/scanner.go", AIComponent},
		{"deep/nested/prompts/foo.txt", AIComponent},
		{"deep/nested/agents/bar.py", AIComponent},
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
	t.Parallel()

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
	t.Parallel()

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
		"agents/scanner.go":    AIComponent,
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
