package iac

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// IAC-153 reports an `actions/upload-artifact` step in a workflow that never
// attests anything. Provenance matters for an artifact someone will consume as
// a build. Two uploads cannot be that (#1010):
//
//   - an upload in a workflow that runs only for pull requests or the merge
//     queue, which publish nothing. pull_request_target is not among them: it
//     runs with the base repository's secrets and can publish;
//   - an upload in a step that runs even when the job failed (`if: always()`,
//     `failure()`, `!cancelled()`). That is how CI keeps diagnostics such as
//     scan reports and test logs, and a failed build is not released.
//
// The rule's absence matcher reports the first upload in the file only, so a
// diagnostic upload that comes first would hide a build upload after it. This
// filter therefore does not just drop: it moves the finding to the first
// upload that could be a build, and drops it only when there is none.

var (
	uploadArtifactRe   = regexp.MustCompile(`(?i)actions/upload-artifact`)
	runsAfterFailureRe = regexp.MustCompile(`(?i)\b(?:always|failure)\(\)|!\s*cancelled\(\)`)
	stepIfRe           = regexp.MustCompile(`^\s*(?:-\s+)?if:\s*(.*)$`)
	workflowOnRe       = regexp.MustCompile(`^(?:on|"on"|'on'|true):\s*(.*)$`)
	eventKeyRe         = regexp.MustCompile(`^\s*(?:-\s+)?([A-Za-z_]+)\s*:?\s*(?:#.*)?$`)
)

// prOnlyEvents are the triggers whose runs publish nothing.
var prOnlyEvents = map[string]bool{"pull_request": true, "merge_group": true}

func relocateIAC153(path string, in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	if len(in) == 0 || !isGitHubActionsFile(path) {
		return in
	}
	var lines []string
	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-153" {
			kept = append(kept, f)
			continue
		}
		if lines == nil {
			lines = strings.Split(string(content), "\n")
		}
		if events := workflowEvents(lines); len(events) > 0 && onlyPullRequestEvents(events) {
			drop(f, "the workflow runs only on "+strings.Join(events, ", ")+
				", which publishes nothing, so the upload is not a build anyone consumes")
			continue
		}
		line, match := firstBuildUpload(lines)
		if line == 0 {
			drop(f, "every upload-artifact step runs even when the job failed "+
				"(if: always(), failure() or !cancelled()), which keeps diagnostics; a failed build is not released")
			continue
		}
		if line != f.Location.StartLine {
			col := strings.Index(lines[line-1], match) + 1
			f.Location.StartLine, f.Location.EndLine = line, line
			f.Location.StartColumn, f.Location.EndColumn = col, col+len(match)
			f.Fingerprint = findings.ComputeFingerprint(f.RuleID, f.Location, match)
		}
		kept = append(kept, f)
	}
	return kept
}

// firstBuildUpload returns the 1-based line of the first upload-artifact
// reference outside a comment whose step does not run after a failure, and the
// text that matched; 0 when there is none.
func firstBuildUpload(lines []string) (int, string) {
	for i, l := range lines {
		loc := uploadArtifactRe.FindStringIndex(l)
		if loc == nil || inYAMLComment(l, loc[0]) {
			continue
		}
		if stepRunsAfterFailure(lines, i) {
			continue
		}
		return i + 1, l[loc[0]:loc[1]]
	}
	return 0, ""
}

// inYAMLComment reports whether byte offset at in l lies after a `#` that
// starts a comment (at line start or after whitespace).
func inYAMLComment(l string, at int) bool {
	for i := 0; i < at; i++ {
		if l[i] == '#' && (i == 0 || l[i-1] == ' ' || l[i-1] == '\t') {
			return true
		}
	}
	return false
}

// stepRunsAfterFailure reports whether the steps-list item holding line i has
// an `if:` that runs it when the job has failed.
func stepRunsAfterFailure(lines []string, i int) bool {
	start := -1
	if strings.HasPrefix(strings.TrimSpace(lines[i]), "-") {
		start = i
	} else {
		ind := indentOf(lines[i])
		for j := i - 1; j >= 0; j-- {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if indentOf(lines[j]) < ind {
				if strings.HasPrefix(t, "-") {
					start = j
				}
				break
			}
		}
	}
	if start < 0 {
		return false
	}
	dash := indentOf(lines[start])
	for k := start; k < len(lines); k++ {
		t := strings.TrimSpace(lines[k])
		if k > start && t != "" && !strings.HasPrefix(t, "#") && indentOf(lines[k]) <= dash {
			break
		}
		if m := stepIfRe.FindStringSubmatch(lines[k]); m != nil && runsAfterFailureRe.MatchString(m[1]) {
			return true
		}
	}
	return false
}

// workflowEvents returns the event names of a workflow's top-level `on:`, in
// its scalar, flow-list or mapping form; nil when there is no `on:`.
func workflowEvents(lines []string) []string {
	for i, l := range lines {
		m := workflowOnRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(stripYAMLComment(m[1]))
		if rest != "" {
			rest = strings.Trim(rest, "[]")
			var out []string
			for _, e := range strings.Split(rest, ",") {
				if e = strings.Trim(strings.TrimSpace(e), `"'`); e != "" {
					out = append(out, e)
				}
			}
			return out
		}
		var out []string
		child := -1
		for _, c := range lines[i+1:] {
			t := strings.TrimSpace(c)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			ind := indentOf(c)
			if ind == 0 {
				break
			}
			if child < 0 {
				child = ind
			}
			if ind != child {
				continue
			}
			if km := eventKeyRe.FindStringSubmatch(c); km != nil {
				out = append(out, km[1])
			}
		}
		return out
	}
	return nil
}

func onlyPullRequestEvents(events []string) bool {
	for _, e := range events {
		if !prOnlyEvents[e] {
			return false
		}
	}
	return true
}

func stripYAMLComment(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		return s[:i]
	}
	if strings.HasPrefix(s, "#") {
		return ""
	}
	return s
}

func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t"))
}
