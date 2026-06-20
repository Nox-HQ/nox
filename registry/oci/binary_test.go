package oci

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeExec(t *testing.T, dir, name string) string {
	t.Helper()
	return writeMode(t, dir, name, 0o755)
}

func writeMode(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestFindPluginBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable-bit resolution is POSIX-specific")
	}

	t.Run("repo-named binary (the taint-analysis case)", func(t *testing.T) {
		dir := t.TempDir()
		writeMode(t, dir, "LICENSE", 0o644)
		writeMode(t, dir, "README.md", 0o644)
		writeMode(t, dir, "plugin.yaml", 0o644)
		want := writeExec(t, dir, "nox-plugin-taint-analysis")

		if got := findPluginBinary(dir, "nox/taint-analysis"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("short-name binary (exact match)", func(t *testing.T) {
		dir := t.TempDir()
		want := writeExec(t, dir, "taint-analysis")
		writeExec(t, dir, "nox-plugin-taint-analysis") // also present; exact wins
		if got := findPluginBinary(dir, "nox/taint-analysis"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("sole executable, unrelated name", func(t *testing.T) {
		dir := t.TempDir()
		writeMode(t, dir, "CHANGELOG.md", 0o644)
		want := writeExec(t, dir, "scanner")
		if got := findPluginBinary(dir, "nox/whatever"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("metadata not chosen as binary", func(t *testing.T) {
		dir := t.TempDir()
		// An executable-bit .sh-less metadata file must never be picked over
		// nothing; with only metadata present we fall back to the short path.
		writeMode(t, dir, "LICENSE", 0o755)
		writeMode(t, dir, "README.md", 0o755)
		got := findPluginBinary(dir, "nox/taint-analysis")
		if got != filepath.Join(dir, "taint-analysis") {
			t.Errorf("got %q, want fallback short-name path", got)
		}
	})
}
