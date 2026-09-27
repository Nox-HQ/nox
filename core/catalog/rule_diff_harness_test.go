package catalog

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The rule-diff workflow reads the harness's exit code: 1 means "rules changed
// and every drop is explained" and passes; 2 and 3 fail. The harness runs under
// `set -e`, so any command that failed unexpectedly exited with ITS status, and
// most commands fail with 1. On #733 an `rm -rf` of a checkout's .git failed
// ("Directory not empty": git was still writing a commit-graph) on the third of
// 25 corpus repositories, the harness exited 1, and the check passed having
// checked three repositories and never reached the ledger. An unexplained drop
// merged behind it.
//
// This reproduces that failure with a stand-in rm and asserts the run cannot
// pass: an unexpected failure is "the harness did not run" (2).
func TestARuleDiffThatCrashesDoesNotPass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the harness is a bash script")
	}
	for _, tool := range []string{"bash", "git", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// A one-commit repository to stand in for a corpus entry.
	repo := filepath.Join(dir, "repo")
	run("git", "init", "-q", repo)
	write(t, filepath.Join(repo, "a.txt"), "hello\n")
	run("git", "-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
	run("git", "-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
	sha := run("git", "-C", repo, "rev-parse", "HEAD")

	corpus := filepath.Join(dir, "corpus.json")
	write(t, corpus, `{"repos":[{"name":"r","url":"file://`+repo+`","sha":"`+sha+`"}]}`)
	ledger := filepath.Join(dir, "ledger.json")
	write(t, ledger, `{"nox_release":"","classifications":{},"entries":[]}`)

	// A nox that reports one finding, and an rm that fails on a .git directory
	// the way it did in CI.
	nox := filepath.Join(dir, "nox")
	write(t, nox, "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -output ] && out=$2; shift; done\n"+
		"mkdir -p \"$out\" && echo '{\"findings\":[{\"RuleID\":\"SEC-001\"}]}' > \"$out/findings.json\"\n")
	shim := filepath.Join(dir, "shim")
	if err := os.Mkdir(shim, 0o755); err != nil {
		t.Fatal(err)
	}
	realRM, err := exec.LookPath("rm")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(shim, "rm"), "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in */.git) "+
		"echo \"rm: cannot remove '$a': Directory not empty\" >&2; exit 1;; esac; done\nexec "+realRM+" \"$@\"\n")
	for _, f := range []string{nox, filepath.Join(shim, "rm")} {
		if err := os.Chmod(f, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A candidate that reports nothing: SEC-001 drops, and the ledger is empty.
	quiet := filepath.Join(dir, "nox-quiet")
	write(t, quiet, "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -output ] && out=$2; shift; done\n"+
		"mkdir -p \"$out\" && echo '{\"findings\":[]}' > \"$out/findings.json\"\n")
	if err := os.Chmod(quiet, 0o755); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("../../scripts/rule-diff.sh")
	if err != nil {
		t.Fatal(err)
	}
	harness := func(cand string, withShim bool) (int, string) {
		cmd := exec.Command("bash", script, nox, cand, corpus, ledger)
		if withShim {
			cmd.Env = append(os.Environ(), "PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		} else if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}

	if code, out := harness(nox, true); code != 2 {
		t.Fatalf("harness exited %d after an unexpected failure, want 2 (did not run); the workflow passes on 1\n%s", code, out)
	}
	// The trap must not touch the answers the harness gives on purpose.
	if code, out := harness(nox, false); code != 0 {
		t.Errorf("no change: harness exited %d, want 0\n%s", code, out)
	}
	if code, out := harness(quiet, false); code != 3 {
		t.Errorf("an unexplained drop: harness exited %d, want 3\n%s", code, out)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
