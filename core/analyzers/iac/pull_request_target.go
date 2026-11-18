package iac

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// decidePullRequestTarget settles IAC-011, IAC-505 and IAC-506 from the
// workflow's triggers rather than from where a word appears.
//
// IAC-011 matched `pull_request_target:` with a colon, so the scalar and list
// forms of `on:` (`on: pull_request_target`, `on: [push, pull_request_target]`)
// were never reported. Its pattern is now the bare word, which also matches a
// comment or an `if: github.event_name == 'pull_request_target'` guard in a
// workflow that does not run on it; this keeps one finding, at the trigger,
// and only when the trigger is real.
//
// IAC-505 (a checkout of the pull request's own commit) is a finding only
// under pull_request_target or workflow_run, which run with the base
// repository's secrets; under pull_request the same checkout is the default.
// IAC-506 (a cache saved) is a finding only in a workflow where IAC-505 holds:
// that cache was written after the fork's code ran, in the base branch's scope.
func decidePullRequestTarget(in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	if !hasAnyRule(in, "IAC-011", "IAC-505", "IAC-506") {
		return in
	}
	lines := strings.Split(string(content), "\n")
	events := workflowEvents(lines)
	prt := containsString(events, "pull_request_target")
	privileged := prt || containsString(events, "workflow_run")
	trigger := triggerLine(lines, "pull_request_target")

	jobs := workflowJobs(lines)
	// The jobs in which a privileged checkout of pull request code stands.
	pwnJobs := map[int]bool{}
	for _, f := range in {
		if f.RuleID != "IAC-505" || !privileged {
			continue
		}
		if !refFetchesCode(lines, f.Location.StartLine) {
			continue
		}
		if j := jobAt(jobs, f.Location.StartLine); j == nil || !j.excludesPrivileged(events) {
			pwnJobs[jobIndex(jobs, f.Location.StartLine)] = true
		}
	}

	out := in[:0]
	var keptIAC011, keptIAC505 bool
	for _, f := range in {
		switch f.RuleID {
		case "IAC-011":
			switch {
			case !prt:
				drop(f, "pull_request_target is mentioned but is not among the workflow's triggers ("+
					strings.Join(events, ", ")+")")
				continue
			case keptIAC011:
				drop(f, "pull_request_target is reported once per workflow, at its trigger")
				continue
			}
			if trigger > 0 {
				f.Location.StartLine, f.Location.EndLine = trigger, trigger
			}
			keptIAC011 = true
		case "IAC-505":
			switch {
			case !privileged:
				drop(f, "the workflow does not run on pull_request_target or workflow_run, so checking out "+
					"the pull request's commit runs it without the base repository's secrets")
				continue
			case !refFetchesCode(lines, f.Location.StartLine):
				drop(f, "the ref is an input of a step that does not check out code "+
					"(only actions/checkout and a reusable workflow call fetch it)")
				continue
			case jobAt(jobs, f.Location.StartLine) != nil && jobAt(jobs, f.Location.StartLine).excludesPrivileged(events):
				drop(f, "the job's if: condition keeps it off pull_request_target and workflow_run runs")
				continue
			case keptIAC505:
				drop(f, "the pull request checkout is reported once per workflow")
				continue
			}
			keptIAC505 = true
		case "IAC-506":
			if !pwnJobs[jobIndex(jobs, f.Location.StartLine)] {
				drop(f, "the job saving this cache does not run pull request code under a privileged trigger, "+
					"so the cache holds only the base branch's own content")
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// triggerLine returns the 1-based line on which event is declared as a
// trigger: the `on:` line for the scalar and list forms, the event's own line
// for the map and sequence forms. It returns 0 when event is not a trigger.
func triggerLine(lines []string, event string) int {
	for i, l := range lines {
		m := workflowOnRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if rest := strings.TrimSpace(stripYAMLComment(m[1])); rest != "" {
			for _, e := range strings.Split(strings.Trim(rest, "[]"), ",") {
				if strings.Trim(strings.TrimSpace(e), `"'`) == event {
					return i + 1
				}
			}
			return 0
		}
		child := -1
		for j := i + 1; j < len(lines); j++ {
			c := lines[j]
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
			if km := eventKeyRe.FindStringSubmatch(c); len(km) > 1 && km[1] == event {
				return j + 1
			}
		}
		return 0
	}
	return 0
}

func hasAnyRule(fs []findings.Finding, ids ...string) bool {
	for _, f := range fs {
		for _, id := range ids {
			if f.RuleID == id {
				return true
			}
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// workflowJob is one entry under `jobs:`, by line span (1-based, inclusive).
type workflowJob struct {
	start, end int
	cond       string // the job-level if:, when there is one
}

var (
	eventNameNotRe = regexp.MustCompile(`github\.event_name\s*!=\s*['"]([a-z_]+)['"]`)
	eventNameIsRe  = regexp.MustCompile(`github\.event_name\s*==\s*['"]([a-z_]+)['"]`)
)

// excludesPrivileged reports whether the job's condition keeps it from
// running on every privileged trigger the workflow has. It reads the two
// forms workflows use, `github.event_name != 'pull_request_target'` and
// `github.event_name == 'push'`, and claims nothing about any other
// condition: an expression it cannot read is not an exclusion.
func (j *workflowJob) excludesPrivileged(events []string) bool {
	if j == nil || j.cond == "" {
		return false
	}
	excluded := map[string]bool{}
	for _, m := range eventNameNotRe.FindAllStringSubmatch(j.cond, -1) {
		if !strings.Contains(j.cond, "||") {
			excluded[m[1]] = true
		}
	}
	if is := eventNameIsRe.FindAllStringSubmatch(j.cond, -1); len(is) > 0 && !strings.Contains(j.cond, "!=") {
		allowed := map[string]bool{}
		for _, m := range is {
			allowed[m[1]] = true
		}
		for _, e := range []string{"pull_request_target", "workflow_run"} {
			if !allowed[e] {
				excluded[e] = true
			}
		}
	}
	for _, e := range events {
		if (e == "pull_request_target" || e == "workflow_run") && !excluded[e] {
			return false
		}
	}
	return true
}

// workflowJobs returns the jobs under the top-level `jobs:` key.
func workflowJobs(lines []string) []workflowJob {
	var jobs []workflowJob
	in, child := false, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(l)
		if ind == 0 {
			if in && len(jobs) > 0 {
				jobs[len(jobs)-1].end = i
			}
			in = strings.HasPrefix(t, "jobs:")
			child = -1
			continue
		}
		if !in {
			continue
		}
		if child < 0 {
			child = ind
		}
		switch {
		case ind == child:
			if len(jobs) > 0 {
				jobs[len(jobs)-1].end = i
			}
			jobs = append(jobs, workflowJob{start: i + 1, end: len(lines)})
		case len(jobs) > 0 && jobs[len(jobs)-1].cond == "" && strings.HasPrefix(t, "if:") && isJobKey(lines, i, jobs[len(jobs)-1].start):
			jobs[len(jobs)-1].cond = strings.TrimSpace(strings.TrimPrefix(t, "if:"))
		}
	}
	return jobs
}

// isJobKey reports whether line i is a direct key of the job that starts at
// the 1-based line start: indented exactly one level below the job's name.
func isJobKey(lines []string, i, start int) bool {
	jobIndent := indentOf(lines[start-1])
	for k := start; k <= i; k++ {
		if t := strings.TrimSpace(lines[k]); t != "" && !strings.HasPrefix(t, "#") {
			return indentOf(lines[i]) == indentOf(lines[k]) && indentOf(lines[k]) > jobIndent
		}
	}
	return false
}

func jobIndex(jobs []workflowJob, line int) int {
	for i := range jobs {
		if line >= jobs[i].start && line <= jobs[i].end {
			return i
		}
	}
	return -1
}

func jobAt(jobs []workflowJob, line int) *workflowJob {
	if i := jobIndex(jobs, line); i >= 0 {
		return &jobs[i]
	}
	return nil
}

var (
	checkoutUsesRe     = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*['"]?actions/checkout@`)
	reusableWorkflowRe = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*['"]?(?:\./|[\w.-]+/[\w.-]+/)\.github/workflows/`)
	usesLineRe         = regexp.MustCompile(`^\s*(?:-\s+)?uses:`)
)

// refFetchesCode reports whether the `ref:` on the 1-based line belongs to a
// step or job that fetches code at that ref: an actions/checkout step, or a
// call to a reusable workflow, which checks out the ref it is passed. A `ref:`
// is also an input of actions that only read a commit's status or metadata
// (lewagon/wait-on-check-action, for one), and those run nothing.
//
// It walks up from the line to the `uses:` of the same step or job: the first
// `uses:` line indented less deeply than the ref's `with:` block.
func refFetchesCode(lines []string, line int) bool {
	if line < 1 || line > len(lines) {
		return false
	}
	refIndent := indentOf(lines[line-1])
	for k := line - 2; k >= 0; k-- {
		l := lines[k]
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if usesLineRe.MatchString(l) && indentOf(l) < refIndent {
			return checkoutUsesRe.MatchString(l) || reusableWorkflowRe.MatchString(l)
		}
		// Reaching the start of the step (`- `) or the job without a uses: line
		// means the ref belongs to something else.
		if strings.HasPrefix(t, "- ") && indentOf(l) < refIndent-2 {
			return false
		}
		if indentOf(l) == 0 {
			return false
		}
	}
	return false
}
