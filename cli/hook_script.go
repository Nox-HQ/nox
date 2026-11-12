package main

import (
	"fmt"
	"strings"
)

// hookSeverities are the severities a hook can gate on, most severe first.
// info is absent on purpose: a hook that refuses a commit over an
// informational note is one the next commit bypasses.
var hookSeverities = []string{"critical", "high", "medium", "low"}

// hookSpec is everything that varies between the hooks nox installs. There are
// two installers, `nox protect install` and `nox install-hook`, and they used
// to carry a script each: one handled the scan's exit code and the other ran
// under `set -e`, which ended the script on that exit code before the line
// that explained it.
type hookSpec struct {
	// kind is the git hook: "pre-commit" scans the index, "pre-push" the
	// working tree.
	kind string
	// bin is the nox to run: a name looked up on PATH, or a path.
	bin string
	// threshold is the least severe severity that blocks.
	threshold string
	// header is the comment under the shebang. `nox protect` finds its own
	// hooks by a marker in it.
	header []string
	// skipIfMissing lets the commit through, with a notice, when bin cannot be
	// found. Without it a missing nox stops the commit as any failed scan does.
	skipIfMissing bool
}

// render writes the hook. The scan's verdict is read from its exit code and
// every outcome is handled explicitly: 0 passes silently, 1 blocks and says
// what to do, anything else stops the commit and says the scan did not
// complete. A crashed scan that let the commit through would be a gate that
// failed and reported success.
func (h hookSpec) render() string {
	action, scope, staged := "commit", "staged files", " --staged"
	if h.kind == "pre-push" {
		action, scope, staged = "push", "the working tree", ""
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, line := range h.header {
		fmt.Fprintf(&b, "# %s\n", line)
	}
	fmt.Fprintf(&b, "\nnox=%s\n", shellQuote(h.bin))
	if h.skipIfMissing {
		fmt.Fprintf(&b, `if ! command -v "$nox" >/dev/null 2>&1; then
    echo "nox: $nox not found; skipping the %s scan" >&2
    exit 0
fi
`, h.kind)
	}
	fmt.Fprintf(&b, `
# Reports go to a directory this hook removes. A scan writes findings.json and
# ai.inventory.json to its output directory, which defaults to the working
# directory: two untracked files in the repository after every %[1]s.
out=$(mktemp -d "${TMPDIR:-/tmp}/nox-hook.XXXXXX") || {
    echo "nox: could not create a temporary directory; the %[1]s is stopped because nothing was scanned" >&2
    exit 2
}
trap 'rm -rf "$out"' EXIT

"$nox" scan .%[2]s --severity-threshold %[3]s --quiet --output "$out"
status=$?
if [ "$status" -eq 1 ]; then
    echo "" >&2
    echo "nox: %[1]s blocked: %[4]s hold findings of severity %[3]s or above" >&2
    echo "nox: see them with: $nox scan .%[2]s --severity-threshold %[3]s" >&2
    echo "nox: waive a false positive in place with '// nox:ignore RULE-ID -- reason'" >&2
    echo "nox: skip this check with 'git %[1]s --no-verify' (not recommended)" >&2
    exit 1
fi
if [ "$status" -ne 0 ]; then
    echo "nox: the %[5]s scan did not complete (exit $status); the %[1]s is stopped because nothing was verified" >&2
    exit "$status"
fi
exit 0
`, action, staged, h.threshold, scope, h.kind)
	return b.String()
}

// shellQuote quotes s as one word for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isValidThreshold returns true if the given string is a severity a hook can
// gate on.
func isValidThreshold(s string) bool {
	for _, sev := range hookSeverities {
		if s == sev {
			return true
		}
	}
	return false
}

// thresholdFromFailOn turns a list of severities into the one threshold a scan
// takes: the least severe severity listed. `--severity-threshold` is a
// minimum, so "critical,high" means "high and above".
//
// The hook used to take the FIRST severity listed, which for the default
// "critical,high" is the most severe: a high-severity finding passed a hook
// that had just announced it would fail on high.
func thresholdFromFailOn(failOn string) (string, error) {
	least := -1
	for _, raw := range strings.Split(failOn, ",") {
		sev := strings.TrimSpace(raw)
		if sev == "" {
			continue
		}
		rank := -1
		for i, known := range hookSeverities {
			if sev == known {
				rank = i
			}
		}
		if rank < 0 {
			return "", fmt.Errorf("unknown severity %q in --fail-on: use %s", sev, strings.Join(hookSeverities, ", "))
		}
		if rank > least {
			least = rank
		}
	}
	if least < 0 {
		return "", fmt.Errorf("--fail-on names no severity: use %s", strings.Join(hookSeverities, ", "))
	}
	return hookSeverities[least], nil
}
