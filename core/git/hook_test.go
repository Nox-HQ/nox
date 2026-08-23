package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHookStatus(t *testing.T) {
	repo := t.TempDir()
	hooksDir := filepath.Join(repo, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(hooksDir, "pre-commit")

	// No hook.
	if state, _ := HookStatus(repo); state != HookNone {
		t.Errorf("no hook: state = %v, want HookNone", state)
	}
	// A foreign hook.
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho other\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if state, _ := HookStatus(repo); state != HookForeign {
		t.Errorf("foreign hook: state = %v, want HookForeign", state)
	}
	// A nox hook (carries the marker).
	if err := os.WriteFile(hook, []byte("#!/bin/sh\n# "+HookMarker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if state, path := HookStatus(repo); state != HookNox || path != hook {
		t.Errorf("nox hook: state = %v path = %s, want HookNox %s", state, path, hook)
	}
}
