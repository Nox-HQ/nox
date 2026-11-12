package cli

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seededToken returns a GitHub-token-shaped string from a fixed seed: the same
// value on every run, and one no person chose.
func seededToken() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(7))
	b := make([]byte, 36)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return "ghp_" + string(b)
}

// stagedSecretRepo returns a repository with one staged file holding a
// high-severity secret, and the secret.
func stagedSecretRepo(t *testing.T) (repo, secret string) {
	t.Helper()
	repo = setupProtectRepo(t)
	secret = seededToken()
	writeTestFile(t, filepath.Join(repo, "svc.py"), "GITHUB_TOKEN = \""+secret+"\"\n")
	gitRun(t, repo, "add", "svc.py")
	return repo, secret
}

// A staged scan that fails printed a count and nothing else, and under --quiet
// (which is how every hook calls it) printed nothing: the commit was refused
// and the only way to learn why was to find and open a JSON file. It names
// what it found, and never the value.
func TestScan_StagedNamesWhatItFound(t *testing.T) {
	for _, quiet := range []bool{true, false} {
		repo, secret := stagedSecretRepo(t)
		args := []string{"scan", repo, "--staged", "--offline", "--severity-threshold", "high", "--output", t.TempDir()}
		if quiet {
			args = append(args, "--quiet")
		}
		var code int
		var stderr string
		captureStdout(t, func() { stderr = captureStderr(t, func() { code = run(args) }) })
		if code != 1 {
			t.Fatalf("quiet=%v: exit %d, want 1", quiet, code)
		}
		for _, want := range []string{"svc.py:1", "SEC-003", "high"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("quiet=%v: stderr does not name %q:\n%s", quiet, want, stderr)
			}
		}
		if strings.Contains(stderr, secret) || strings.Contains(stderr, secret[4:16]) {
			t.Errorf("quiet=%v: the scan printed the secret it found", quiet)
		}
	}
}

// Below the threshold nothing gates, so nothing is named: a list of findings
// under a passing commit would read as the reason for a block that did not
// happen.
func TestScan_StagedBelowThresholdNamesNothing(t *testing.T) {
	repo, _ := stagedSecretRepo(t)
	var code int
	var stderr string
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = run([]string{"scan", repo, "--staged", "--offline", "--quiet", "--severity-threshold", "critical", "--output", t.TempDir()})
		})
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0: a high finding does not meet a critical threshold", code)
	}
	if strings.Contains(stderr, "svc.py") {
		t.Errorf("a passing scan named a finding:\n%s", stderr)
	}
}

// `--severity-threshold hihg` matched no severity, so no finding met it and the
// scan exited 0 with a secret staged. A mistyped gate is not a lenient gate.
func TestScan_UnknownThresholdIsAnError(t *testing.T) {
	repo, _ := stagedSecretRepo(t)
	for _, tc := range [][]string{
		{"--severity-threshold", "hihg"},
		{"--severity-threshold", "HIGH"},
		{"--min-confidence", "hihg"},
	} {
		out := filepath.Join(t.TempDir(), "out")
		args := append([]string{"scan", repo, "--staged", "--offline", "--quiet", "--output", out}, tc...)
		var code int
		stderr := captureStderr(t, func() { code = run(args) })
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", tc, code)
		}
		if !strings.Contains(stderr, tc[1]) {
			t.Errorf("%v: the error does not quote the value: %q", tc, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%v: reports were written for a scan that should not have run", tc)
		}
	}
}
