package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The registry cache being unreachable from `cache clear` was a real trap:
// after the index moved repositories, `plugin search` reported stale versions
// while the live index served new ones, and the only remedy was deleting the
// directory by hand.
func TestRemoveCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)

	dir := filepath.Join(noxHome(), "cache", "registry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeCacheDir("registry"); err != nil {
		t.Fatalf("removeCacheDir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("registry cache should be gone")
	}
}

// "clear" describes an end state, so a cache that was never created is success,
// not an error the user has to interpret.
func TestRemoveCacheDirIsIdempotent(t *testing.T) {
	t.Setenv("NOX_HOME", t.TempDir())
	for i := 0; i < 2; i++ {
		if err := removeCacheDir("registry"); err != nil {
			t.Fatalf("call %d on a missing dir should succeed, got %v", i+1, err)
		}
	}
}

// Installed plugins are EXECUTED from the artifacts cache (state.json records a
// binary_path pointing into it), so clearing it does not merely force a
// re-download — it breaks every installed plugin. It must stay put unless the
// operator explicitly asks.
func TestClearLeavesArtifactsAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)

	art := filepath.Join(noxHome(), "cache", "artifacts")
	if err := os.MkdirAll(art, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(art, "plugin-binary")
	if err := os.WriteFile(bin, []byte("ELF"), 0o755); err != nil { // nox:ignore -- test fixture, not a real binary
		t.Fatal(err)
	}

	if rc := runCacheClear(nil); rc != 0 {
		t.Fatalf("clear returned %d", rc)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Error("an installed plugin binary must survive `cache clear` — clearing it breaks the install")
	}
}

func TestClearArtifactsWhenAskedExplicitly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)

	art := filepath.Join(noxHome(), "cache", "artifacts")
	if err := os.MkdirAll(art, 0o755); err != nil {
		t.Fatal(err)
	}
	if rc := runCacheClear([]string{"--artifacts"}); rc != 0 {
		t.Fatalf("clear --artifacts returned %d", rc)
	}
	if _, err := os.Stat(art); !os.IsNotExist(err) {
		t.Error("--artifacts should remove the artifact cache")
	}
}

func TestDirSizeOfMissingDirIsZero(t *testing.T) {
	n, err := dirSize(filepath.Join(t.TempDir(), "nope"))
	if err != nil || n != 0 {
		t.Errorf("dirSize(missing) = (%d, %v), want (0, nil)", n, err)
	}
}
