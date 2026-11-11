package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// hookRun is what executing an installed hook did.
type hookRun struct {
	exit   int
	stderr string
	// args are the arguments the hook passed to nox, one per element. Empty
	// when the hook never reached nox.
	args []string
	// reportDirGone is true when the directory the hook passed as --output no
	// longer exists after the hook finished.
	reportDirGone bool
}

// stubNox writes an executable standing in for nox: it records its arguments,
// writes a report into the directory named by --output the way a scan does, and
// exits with stubExit. It returns the stub's path and the file its arguments
// land in. The directory name has a space in it, because a path with a space is
// the first thing an unquoted substitution in a shell script breaks on.
func stubNox(t *testing.T, stubExit string) (bin, argsFile string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "nox")
	script := `#!/bin/sh
printf '%s\n' "$@" > '` + argsFile + `'
prev=
for a in "$@"; do
  if [ "$prev" = "--output" ]; then echo '{}' > "$a/findings.json"; fi
  prev=$a
done
exit ` + stubExit + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

// runHook executes the hook at hookPath from inside repo, with the stub's
// directory first on PATH.
func runHook(t *testing.T, repo, hookPath, stubBin, argsFile string) hookRun {
	t.Helper()
	cmd := exec.Command("sh", hookPath)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PATH="+filepath.Dir(stubBin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := hookRun{stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	default:
		t.Fatalf("running hook: %v", err)
	}
	if raw, err := os.ReadFile(argsFile); err == nil {
		res.args = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	for i, a := range res.args {
		if a == "--output" && i+1 < len(res.args) {
			_, statErr := os.Stat(res.args[i+1])
			res.reportDirGone = os.IsNotExist(statErr)
		}
	}
	return res
}

// argAfter returns the argument following flag, or "" when flag is absent.
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func skipWithoutSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hook is a POSIX shell script")
	}
}

// installHook runs `nox install-hook` against a fresh repository and returns
// the repository and the hook's path.
func installHook(t *testing.T, kind string, extra ...string) (repo, hookPath string, code int) {
	t.Helper()
	repo = setupProtectRepo(t)
	args := append([]string{"install-hook", "--repo", repo, "--kind", kind}, extra...)
	captureStdout(t, func() { code = run(args) })
	return repo, filepath.Join(repo, ".git", "hooks", kind), code
}

// The default was `--fail-on critical,high`, and the hook asked the scan for
// `$(echo critical,high | cut -d, -f1)`: the FIRST severity listed, which is
// the most severe one. A high-severity finding passed a hook that had just
// printed "Hook will fail on findings of severity: critical,high".
func TestInstallHook_ThresholdIsTheLeastSevereListed(t *testing.T) {
	skipWithoutSh(t)
	tests := []struct {
		failOn string
		want   string
	}{
		{"critical,high", "high"},
		{"high,critical", "high"},
		{"critical", "critical"},
		{"critical, high ,medium", "medium"},
		{"low", "low"},
	}
	for _, tc := range tests {
		t.Run(tc.failOn, func(t *testing.T) {
			bin, argsFile := stubNox(t, "0")
			repo, hook, code := installHook(t, "pre-commit", "--bin", bin, "--fail-on", tc.failOn)
			if code != 0 {
				t.Fatalf("install-hook exit %d, want 0", code)
			}
			got := runHook(t, repo, hook, bin, argsFile)
			if th := argAfter(got.args, "--severity-threshold"); th != tc.want {
				t.Errorf("--fail-on %q: the hook scans at threshold %q, want %q (args %q)", tc.failOn, th, tc.want, got.args)
			}
		})
	}
}

func TestInstallHook_DefaultThresholdIsHigh(t *testing.T) {
	skipWithoutSh(t)
	bin, argsFile := stubNox(t, "0")
	repo, hook, code := installHook(t, "pre-commit", "--bin", bin)
	if code != 0 {
		t.Fatalf("install-hook exit %d, want 0", code)
	}
	got := runHook(t, repo, hook, bin, argsFile)
	if th := argAfter(got.args, "--severity-threshold"); th != "high" {
		t.Errorf("default hook scans at threshold %q, want high", th)
	}
}

func TestInstallHook_RejectsUnknownSeverity(t *testing.T) {
	for _, failOn := range []string{"critical,hihg", "HIGH", "", ",", "info"} {
		var code int
		var repo, hook string
		stderr := captureStderr(t, func() { repo, hook, code = installHook(t, "pre-commit", "--fail-on", failOn) })
		if code != 2 {
			t.Errorf("--fail-on %q: exit %d, want 2", failOn, code)
		}
		if _, err := os.Stat(hook); err == nil {
			t.Errorf("--fail-on %q: a hook was written to %s for a threshold nox cannot honour", failOn, repo)
		}
		if !strings.Contains(stderr, "critical, high, medium, low") {
			t.Errorf("--fail-on %q: the error does not name the valid severities: %q", failOn, stderr)
		}
	}
}

// What the hook does with each scan outcome. The old script ran under `set -e`,
// so the scan's exit 1 ended the script before the line that printed why: the
// commit was refused with no output at all.
func TestHooks_ExitCodeAndMessage(t *testing.T) {
	skipWithoutSh(t)
	type install func(t *testing.T, bin string) (repo, hook string)
	installers := map[string]install{
		"install-hook pre-commit": func(t *testing.T, bin string) (string, string) {
			repo, hook, _ := installHook(t, "pre-commit", "--bin", bin)
			return repo, hook
		},
		"install-hook pre-push": func(t *testing.T, bin string) (string, string) {
			repo, hook, _ := installHook(t, "pre-push", "--bin", bin)
			return repo, hook
		},
		"protect install": func(t *testing.T, _ string) (string, string) {
			repo := setupProtectRepo(t)
			var code int
			captureStdout(t, func() { code = run([]string{"protect", "install", repo}) })
			if code != 0 {
				t.Fatalf("protect install exit %d", code)
			}
			return repo, filepath.Join(repo, ".git", "hooks", "pre-commit")
		},
	}
	outcomes := []struct {
		name     string
		scanExit string
		wantExit int
		wantSaid string // "" means the hook must print nothing
	}{
		{"clean scan passes silently", "0", 0, ""},
		{"findings block and say so", "1", 1, "blocked"},
		{"a scan that errored stops the commit and says so", "2", 2, "did not complete"},
	}
	for name, inst := range installers {
		for _, oc := range outcomes {
			t.Run(name+"/"+oc.name, func(t *testing.T) {
				bin, argsFile := stubNox(t, oc.scanExit)
				repo, hook := inst(t, bin)
				got := runHook(t, repo, hook, bin, argsFile)
				if got.exit != oc.wantExit {
					t.Errorf("hook exit %d, want %d (stderr %q)", got.exit, oc.wantExit, got.stderr)
				}
				if oc.wantSaid == "" && strings.TrimSpace(got.stderr) != "" {
					t.Errorf("hook printed %q on a clean scan", got.stderr)
				}
				if oc.wantSaid != "" && !strings.Contains(got.stderr, oc.wantSaid) {
					t.Errorf("hook stderr %q does not say %q", got.stderr, oc.wantSaid)
				}
			})
		}
	}
}

// A scan writes findings.json and ai.inventory.json into its output directory,
// which defaults to the working directory. Run from a hook that left two
// untracked files in the repository after every commit, and the next scan read
// them. The hooks send reports to a directory they remove.
func TestHooks_LeaveNoReportBehind(t *testing.T) {
	skipWithoutSh(t)
	for _, kind := range []string{"pre-commit", "pre-push"} {
		t.Run(kind, func(t *testing.T) {
			bin, argsFile := stubNox(t, "1")
			repo, hook, _ := installHook(t, kind, "--bin", bin)
			got := runHook(t, repo, hook, bin, argsFile)
			out := argAfter(got.args, "--output")
			if out == "" {
				t.Fatalf("the hook did not pass --output: %q", got.args)
			}
			if rel, err := filepath.Rel(repo, out); err == nil && !strings.HasPrefix(rel, "..") {
				t.Errorf("the hook writes reports inside the repository: %s", out)
			}
			if !got.reportDirGone {
				t.Errorf("the report directory %s outlived the hook", out)
			}
			for _, name := range []string{"findings.json", "ai.inventory.json"} {
				if _, err := os.Stat(filepath.Join(repo, name)); err == nil {
					t.Errorf("the hook left %s in the repository", name)
				}
			}
		})
	}
}

func TestInstallHook_PreCommitScansTheIndexAndPrePushTheTree(t *testing.T) {
	skipWithoutSh(t)
	for kind, wantStaged := range map[string]bool{"pre-commit": true, "pre-push": false} {
		bin, argsFile := stubNox(t, "0")
		repo, hook, _ := installHook(t, kind, "--bin", bin)
		got := runHook(t, repo, hook, bin, argsFile)
		staged := false
		for _, a := range got.args {
			staged = staged || a == "--staged"
		}
		if staged != wantStaged {
			t.Errorf("%s: --staged passed = %v, want %v (args %q)", kind, staged, wantStaged, got.args)
		}
	}
}

// A hook that cannot find nox says so and lets the commit through: it is a
// local convenience, and refusing every commit on a machine where nox was
// uninstalled would be answered with --no-verify for good.
func TestInstallHook_MissingBinarySkipsLoudly(t *testing.T) {
	skipWithoutSh(t)
	bin, argsFile := stubNox(t, "1")
	missing := filepath.Join(t.TempDir(), "not-nox")
	repo, hook, _ := installHook(t, "pre-commit", "--bin", missing)
	got := runHook(t, repo, hook, bin, argsFile)
	if got.exit != 0 {
		t.Errorf("hook exit %d, want 0", got.exit)
	}
	if !strings.Contains(got.stderr, "not found") {
		t.Errorf("hook skipped without saying why: %q", got.stderr)
	}
	if len(got.args) != 0 {
		t.Errorf("hook ran a nox it was not pointed at: %q", got.args)
	}
}
