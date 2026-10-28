package testenv

import (
	"os"
	"path/filepath"
	"testing"
)

// unset clears key for the test and restores it afterwards.
func unset(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	_ = os.Unsetenv(key)
}

func TestPinGoToolchainDirsUsesTheRealHome(t *testing.T) {
	for _, k := range []string{"GOCACHE", "GOPATH", "GOENV"} {
		unset(t, k)
	}
	cache, _ := os.UserCacheDir()
	home, _ := os.UserHomeDir()
	config, _ := os.UserConfigDir()

	pinGoToolchainDirs()
	// Moving HOME afterwards must not move the pinned directories.
	t.Setenv("HOME", t.TempDir())

	for key, want := range map[string]string{
		"GOCACHE": filepath.Join(cache, "go-build"),
		"GOPATH":  filepath.Join(home, "go"),
		"GOENV":   filepath.Join(config, "go", "env"),
	} {
		if got := os.Getenv(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestPinGoToolchainDirsKeepsExplicitValues(t *testing.T) {
	t.Setenv("GOCACHE", "/explicit/cache")
	t.Setenv("GOPATH", "/explicit/gopath")
	t.Setenv("GOENV", "off")

	pinGoToolchainDirs()

	for key, want := range map[string]string{"GOCACHE": "/explicit/cache", "GOPATH": "/explicit/gopath", "GOENV": "off"} {
		if got := os.Getenv(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
