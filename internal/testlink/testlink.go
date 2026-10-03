// Package testlink creates symbolic links for tests without letting their
// coverage disappear silently.
//
// A test that needs a link used to skip when the OS refused one. CI runs
// `go test` without -v, so a skip prints nothing, and whether the Windows job
// had exercised the symlinked-root fix (#801) at all was unknowable from its
// green tick. On CI a refused link is now a failure: the job proves the
// coverage or says it is missing. A developer machine without link support
// still skips.
package testlink

import (
	"os"
	"testing"
)

// Symlink creates link -> target, or ends the test.
func Symlink(t testing.TB, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("cannot create a symlink on CI, so this test's coverage would silently skip: %v", err)
	}
	t.Skipf("symlinks unavailable: %v", err)
}
