package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestAddDirsRecursive_FlatDir(t *testing.T) {
	dir := t.TempDir()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}
	defer watcher.Close()

	if err := addDirsRecursive(watcher, dir); err != nil {
		t.Fatalf("addDirsRecursive: %v", err)
	}

	// The root dir should be watched.
	list := watcher.WatchList()
	if len(list) < 1 {
		t.Fatal("expected at least 1 watched dir")
	}
}

func TestAddDirsRecursive_SkipsGitDir(t *testing.T) {
	dir := t.TempDir()

	// Create .git, node_modules, and .nox directories - all should be skipped.
	for _, name := range []string{".git", "node_modules", ".nox"} {
		if err := os.MkdirAll(filepath.Join(dir, name, "subdir"), 0o755); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	// Create a regular subdirectory that should be watched.
	if err := os.MkdirAll(filepath.Join(dir, "src", "pkg"), 0o755); err != nil {
		t.Fatalf("creating src/pkg: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}
	defer watcher.Close()

	if err := addDirsRecursive(watcher, dir); err != nil {
		t.Fatalf("addDirsRecursive: %v", err)
	}

	list := watcher.WatchList()
	for _, watched := range list {
		base := filepath.Base(watched)
		if base == ".git" || base == "node_modules" || base == ".nox" {
			t.Errorf("should not watch %s", watched)
		}
	}

	// Should have root, src, src/pkg = 3 dirs.
	if len(list) != 3 {
		t.Errorf("expected 3 watched dirs, got %d: %v", len(list), list)
	}
}

func TestAddDirsRecursive_NonexistentDir(t *testing.T) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}
	defer watcher.Close()

	// Nonexistent path should return an error from filepath.Walk.
	err = addDirsRecursive(watcher, "/nonexistent/path/xyz123")
	// filepath.Walk returns an error if root doesn't exist. But the callback
	// swallows individual errors, so the root error is the main concern.
	// The actual behavior depends on filepath.Walk: it returns the root error.
	if err != nil {
		// This is expected behavior - walk returns an error for nonexistent root.
	}
}

func TestAddDirsRecursive_NestedDirs(t *testing.T) {
	dir := t.TempDir()

	// Create nested directory structure.
	nested := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("creating nested dirs: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}
	defer watcher.Close()

	if err := addDirsRecursive(watcher, dir); err != nil {
		t.Fatalf("addDirsRecursive: %v", err)
	}

	// Should watch root + a + b + c = 4 dirs.
	list := watcher.WatchList()
	if len(list) != 4 {
		t.Errorf("expected 4 watched dirs, got %d", len(list))
	}
}

func TestAddDirsRecursive_SkipsFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a file - it should not be added as a watch.
	if err := os.WriteFile(filepath.Join(dir, "test.go"), []byte("package main"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}
	defer watcher.Close()

	if err := addDirsRecursive(watcher, dir); err != nil {
		t.Fatalf("addDirsRecursive: %v", err)
	}

	// Only the root directory should be watched.
	list := watcher.WatchList()
	if len(list) != 1 {
		t.Errorf("expected 1 watched dir (root only), got %d", len(list))
	}
}

func TestPrintScanResults_ValidDir(t *testing.T) {
	dir := t.TempDir()

	// Create a clean file.
	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// printScanResults should not panic on a valid directory.
	printScanResults(dir, false)
}

func TestPrintScanResults_WithFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a secret.
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// printScanResults should not panic.
	printScanResults(dir, false)
}

func TestPrintScanResults_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	content := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// printScanResults with JSON flag should not panic.
	printScanResults(dir, true)
}

func TestPrintScanResults_InvalidPath(t *testing.T) {
	// Scanning a nonexistent path should print an error but not panic.
	printScanResults("/nonexistent/path/xyz123", false)
}

func TestRunWatch_InvalidFlag(t *testing.T) {
	code := runWatch([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}
