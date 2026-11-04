package deps

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	fixtureOnce sync.Once
	fixturePath string
	fixtureErr  error
	fixtureLog  []byte
)

// buildGoFixture builds testdata/gobin once per test run and returns the
// executable's path. It links golang.org/x/sync, so its build info names a
// module at the version this repository's go.mod requires.
func buildGoFixture(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nox-gobin-")
		if err != nil {
			fixtureErr = err
			return
		}
		fixturePath = filepath.Join(dir, "gobin")
		cmd := exec.Command("go", "build", "-o", fixturePath, "./testdata/gobin")
		fixtureLog, fixtureErr = cmd.CombinedOutput()
	})
	if fixtureErr != nil {
		t.Fatalf("building the Go fixture: %v\n%s", fixtureErr, fixtureLog)
	}
	return fixturePath
}
