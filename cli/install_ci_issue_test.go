package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The generated workflow's issue step is shell, and shell that is never run is
// shell that is never tested. These tests execute the step's own script, taken
// from the rendered workflow, with the real `nox advisories` (this test binary
// re-entered as the CLI) and a stand-in for `gh` that keeps issues in a
// directory. What they cannot show is GitHub itself: that the runner provides
// jq, that `gh issue list` returns what the stand-in returns, or that the
// Actions cache is evicted when documented. None of this ran on GitHub.

// TestHelperProcessNox lets the generated script's `nox` be the code under test.
func TestHelperProcessNox(t *testing.T) {
	if os.Getenv("NOX_TEST_AS_CLI") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			os.Exit(runAdvisories(args[i+1:]))
		}
	}
	os.Exit(2)
}

const reportStep = "Report advisories in an issue"

type issueHarness struct {
	t      *testing.T
	dir    string // workspace: nox-results/, fake gh state
	bin    string // PATH dir with nox and gh stand-ins
	script string
}

func newIssueHarness(t *testing.T) *issueHarness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the generated step runs on ubuntu runners; its shell stand-ins are POSIX")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s is required to test the generated workflow", tool)
			}
			t.Skipf("%s not installed; the generated workflow's shell cannot be exercised", tool)
		}
	}
	_, steps := renderedAdvisoriesSteps(t)
	step, ok := steps[reportStep]
	if !ok {
		t.Fatalf("workflow has no %q step", reportStep)
	}
	if strings.Contains(step.If, "previous-run") {
		t.Fatalf("the issue step must not be gated on a previous run existing: if = %q", step.If)
	}
	if strings.Contains(step.Run, "${{") {
		t.Fatalf("the step script must be runnable without GitHub expressions:\n%s", step.Run)
	}

	h := &issueHarness{t: t, dir: t.TempDir(), bin: t.TempDir(), script: step.Run}
	if err := os.MkdirAll(filepath.Join(h.dir, "nox-results"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(h.bin, "nox"), fmt.Sprintf(
		"#!/bin/bash\nNOX_TEST_AS_CLI=1 exec %q -test.run='^TestHelperProcessNox$' -- \"$@\"\n", exe), 0o755)
	// gh: `issue list` prints every stored body; `issue create` stores one.
	h.write(filepath.Join(h.bin, "gh"), `#!/bin/bash
set -eu
store="${FAKE_GH_DIR}/issues"
mkdir -p "$store"
if [ "$1 $2" = "issue list" ]; then
  for f in "$store"/*.md; do [ -e "$f" ] && { cat "$f"; echo; }; done
  exit 0
fi
if [ "$1 $2" = "issue create" ]; then
  title=""; body=""
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in --title) title="$2"; shift 2;; --body-file) body="$2"; shift 2;; *) shift;; esac
  done
  n=$(ls "$store" | wc -l | tr -d ' ')
  { echo "$title"; cat "$body"; } > "$store/issue-$n.md"
  echo "$title" >> "${FAKE_GH_DIR}/created.log"
  exit 0
fi
echo "unexpected gh call: $*" >&2; exit 9
`, 0o755)
	return h
}

func (h *issueHarness) write(path, body string, mode os.FileMode) {
	h.t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		h.t.Fatal(err)
	}
}

// run executes the step. previous is nil for "no previous run" (cache miss).
func (h *issueHarness) run(current, previous []findings.Finding) {
	h.t.Helper()
	writeReport(h.t, filepath.Join(h.dir, "nox-results", "findings.json"), current)
	prevPath := filepath.Join(h.dir, "nox-previous", "findings.json")
	_ = os.RemoveAll(filepath.Join(h.dir, "nox-previous"))
	if previous != nil {
		if err := os.MkdirAll(filepath.Dir(prevPath), 0o755); err != nil {
			h.t.Fatal(err)
		}
		writeReport(h.t, prevPath, previous)
	}
	cmd := exec.Command("bash", "-c", h.script)
	cmd.Dir = h.dir
	cmd.Env = append(os.Environ(),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GH_DIR="+h.dir,
		"PREVIOUS="+prevPath,
		"POLICY_OVERRIDE=",
		"GH_TOKEN=unused",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("step failed: %v\n%s", err, out)
	}
}

func (h *issueHarness) created() []string {
	raw, err := os.ReadFile(filepath.Join(h.dir, "created.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (h *issueHarness) issueText() string {
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(h.dir, "issues", "*.md"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		b.Write(raw)
	}
	return b.String()
}

func adv(id, pkg string) findings.Finding {
	return advFinding(id, pkg, "1.0.1", findings.SeverityHigh)
}

// The defect: the issue step ran only when a previous run was restored, so an
// Actions cache evicted after seven days made every advisory disclosed in the
// gap look like part of a first run, and a first run opened nothing.
func TestInstallCIIssueStepReportsWhenThePreviousRunIsGone(t *testing.T) {
	h := newIssueHarness(t)
	h.run([]findings.Finding{adv("GHSA-aaaa", "alpha"), adv("GHSA-bbbb", "beta")}, nil)

	got := h.created()
	if len(got) != 1 {
		t.Fatalf("a cache miss must still open one issue, got %v", got)
	}
	text := h.issueText()
	for _, want := range []string{"GHSA-aaaa", "GHSA-bbbb", "no previous run", "<!-- nox-advisory:npm/alpha/GHSA-aaaa -->", "<!-- nox-advisory:npm/beta/GHSA-bbbb -->"} {
		if !strings.Contains(text, want) {
			t.Errorf("issue is missing %q:\n%s", want, text)
		}
	}
}

// A second miss, or a re-run, must not file the same advisories again.
func TestInstallCIIssueStepDoesNotRepeatWhatIsAlreadyInAnIssue(t *testing.T) {
	h := newIssueHarness(t)
	cur := []findings.Finding{adv("GHSA-aaaa", "alpha")}
	h.run(cur, nil)
	h.run(cur, nil)
	h.run(cur, cur) // and with a previous run that already knows it
	if got := h.created(); len(got) != 1 {
		t.Fatalf("the same advisory was reported %d times: %v", len(got), got)
	}
}

// Only the advisory no issue mentions is reported, and a closed issue counts: a
// person who closed it has decided, and eviction must not reopen the question.
func TestInstallCIIssueStepReportsOnlyTheUnrecordedAdvisory(t *testing.T) {
	h := newIssueHarness(t)
	h.run([]findings.Finding{adv("GHSA-aaaa", "alpha")}, nil)

	h.run([]findings.Finding{adv("GHSA-aaaa", "alpha"), adv("GHSA-cccc", "gamma")}, nil)
	got := h.created()
	if len(got) != 2 || !strings.HasPrefix(got[1], "nox: 1 ") {
		t.Fatalf("want a second issue for exactly one advisory, got %v", got)
	}
	files, _ := filepath.Glob(filepath.Join(h.dir, "issues", "*.md"))
	second, _ := os.ReadFile(files[len(files)-1])
	if strings.Contains(string(second), "GHSA-aaaa") || !strings.Contains(string(second), "GHSA-cccc") {
		t.Fatalf("the second issue must hold only the new advisory:\n%s", second)
	}
}

// With a previous run the behaviour is what it always was: new advisories only.
func TestInstallCIIssueStepWithAPreviousRunReportsOnlyNew(t *testing.T) {
	h := newIssueHarness(t)
	old := adv("GHSA-aaaa", "alpha")
	h.run([]findings.Finding{old, adv("GHSA-dddd", "delta")}, []findings.Finding{old})
	got := h.created()
	if len(got) != 1 || !strings.Contains(got[0], "newly disclosed") {
		t.Fatalf("got %v", got)
	}
	if text := h.issueText(); strings.Contains(text, "GHSA-aaaa") || !strings.Contains(text, "GHSA-dddd") {
		t.Fatalf("only the new advisory belongs in the issue:\n%s", text)
	}
}

func TestInstallCIIssueStepIsQuietWhenNothingIsOutstanding(t *testing.T) {
	h := newIssueHarness(t)
	old := adv("GHSA-aaaa", "alpha")
	h.run([]findings.Finding{old}, []findings.Finding{old})
	h.run(nil, nil)
	if got := h.created(); len(got) != 0 {
		t.Fatalf("nothing is outstanding, got %v", got)
	}
}
