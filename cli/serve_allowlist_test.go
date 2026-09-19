package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The MCP server is the surface an agent drives, so the interesting question is
// not whether --allowed-paths works — server_test.go establishes that — but what
// happens when nobody passes it. It used to mean "anywhere": the released 1.37.0
// binary answered tools/call scan{"path": "/etc"} with a scan of /etc.
//
// What this asserts is narrow and load-bearing: the CLI never hands server.New a
// zero-length allowlist, because one layer down that reads as unrestricted.
func TestServeConfinesItselfWhenNoPathsAreGiven(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	paths, err := serveAllowedPaths("")
	if err != nil {
		t.Fatalf("serveAllowedPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected exactly one root, got %v", paths)
	}

	// t.Chdir reports the logical path; on macOS /tmp is a symlink to
	// /private/tmp, so compare resolved forms rather than strings.
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	got, err := filepath.EvalSymlinks(paths[0])
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if got != want {
		t.Fatalf("expected the working directory %q, got %q", want, got)
	}
}

// Widening stays possible, because a client that legitimately serves several
// checkouts must not have to run several servers.
func TestExplicitPathsAreStillHonoured(t *testing.T) {
	paths, err := serveAllowedPaths(" /one , ,/two ")
	if err != nil {
		t.Fatalf("serveAllowedPaths: %v", err)
	}
	if len(paths) != 2 || paths[0] != "/one" || paths[1] != "/two" {
		t.Fatalf("expected [/one /two], got %v", paths)
	}
}

// The old unrestricted behaviour is reachable, but only by naming it. The
// difference from before is that it now appears in the process table.
func TestRootIsHowYouAskForEverything(t *testing.T) {
	paths, err := serveAllowedPaths("/")
	if err != nil {
		t.Fatalf("serveAllowedPaths: %v", err)
	}
	if len(paths) != 1 || paths[0] != "/" {
		t.Fatalf("expected [/], got %v", paths)
	}
}

// If the working directory cannot be resolved we must not quietly fall back to
// the empty allowlist, because empty means unrestricted one layer down.
func TestAnUnresolvableWorkingDirectoryRefusesRatherThanFailsOpen(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "gone")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(sub)
	if err := os.Remove(sub); err != nil {
		t.Skipf("cannot remove the working directory on this platform: %v", err)
	}

	paths, err := serveAllowedPaths("")
	if err == nil {
		// Some platforms still resolve a deleted working directory. The
		// invariant that has to hold either way is that we never return an
		// empty allowlist.
		if len(paths) == 0 {
			t.Fatal("returned an empty allowlist, which the server reads as unrestricted")
		}
		return
	}
	if !strings.Contains(err.Error(), "--allowed-paths") {
		t.Fatalf("the error should tell the operator how to recover, got: %v", err)
	}
}
