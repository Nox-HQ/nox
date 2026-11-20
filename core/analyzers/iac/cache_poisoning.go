package iac

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// IAC-507: cross-workflow cache poisoning, the shape of the May 2026 TanStack
// compromise.
//
// Two workflows, neither wrong alone. Workflow A runs on a trigger that
// executes in the BASE repository's cache scope (pull_request_target,
// workflow_run, issue_comment), checks out a fork's code, and saves a cache.
// Workflow B is a release workflow that restores a cache A's save can match and
// can publish. The fork's code writes the cache; the release restores it.
//
// What GitHub says about scope (docs.github.com, dependency caching): a run
// restores caches from its own ref and the default branch; a cache created on
// `pull_request` belongs to refs/pull/N/merge and "cannot be restored by the
// base branch or other pull requests". So plain pull_request is not a writer
// here. And, importantly: runs from pull_request_target, issue_comment and
// workflow_run now get READ-ONLY cache access by default, unless the workflow
// or job declares `cache-mode: write` or `write-only`. A writer that opts in is
// certain (high confidence); one that does not is the pre-restriction shape and
// is reported at low confidence, saying so.
//
// The rule needs every workflow of a scan, so it runs from ScanArtifacts; a
// single buffer (MCP, LSP) cannot answer it.

const crossWorkflowCacheRuleID = "IAC-507"

// pwnRefPattern matches a checkout `ref:` that names the pull request's own
// commit. IAC-505 reports it under a privileged trigger, and IAC-507 uses it to
// tell a workflow that runs a fork's code from one that only reacts to a
// trigger, so the two cannot disagree about what a pwn checkout is.
const pwnRefPattern = `(?im)^[ \t]*(?:-[ \t]+)?ref:[ \t]*['"]?[^#\n]*(?:\$\{\{[^}\n]*\b(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch))\b[^}\n]*\}\}|refs/pull/)`

// crossWorkflowCacheRule is registered for its metadata; the analyzer evaluates
// it across files. See the `catalog` field on Analyzer.
func crossWorkflowCacheRule() *rules.Rule {
	return &rules.Rule{
		ID:          crossWorkflowCacheRuleID,
		Version:     "1.0",
		Description: "Release workflow restores a cache that a pull request workflow can write (cross-workflow cache poisoning)",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"iac", "github-actions", "ci-cd", "supply-chain"},
		Metadata:    map[string]string{"cwe": "CWE-345"},
		Remediation: "Make the release workflow's cache restore-only from a trusted writer: key it with something only a push to the default branch can produce, or drop the cache from the job that publishes. On the writing side, do not save a cache from a pull_request_target, workflow_run or issue_comment job that checked out the pull request's code, and leave cache-mode at its read default.",
		References: []string{
			"https://safedep.io/tanstack-github-actions-cache-poisoning/",
			"https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching",
			"https://cwe.mitre.org/data/definitions/345.html",
		},
	}
}

// lowTrustWriters are the events whose runs use the base repository's cache
// scope and are started by someone outside it. IAC-505 judges the first two;
// issue_comment is added because its runs check out `refs/pull/N/head` the same
// way.
var lowTrustWriters = []string{"pull_request_target", "workflow_run", "issue_comment"}

// cacheEntry is one step that restores or saves a cache.
type cacheEntry struct {
	line        int
	family      string // "actions/cache" or the setup action's name
	pm          string // for a setup action: the package manager it caches
	key         string
	restoreKeys []string
	save        bool
	restore     bool
}

// cacheWriter is a cache save inside a job that runs a fork's code.
type cacheWriter struct {
	cacheEntry
	trigger  string
	explicit string // the cache-mode that makes the write real; "" when defaulted
}

// cacheRestore is a restore that a publishing job's credentials can reach.
type cacheRestore struct {
	cacheEntry
	publishes string // what the publishing job holds
}

// workflowCacheFacts is all one workflow contributes to IAC-507. Nil for a
// workflow that contributes nothing, so the scan holds no bytes for it.
type workflowCacheFacts struct {
	path     string
	events   []string
	writers  []cacheWriter
	restores []cacheRestore
}

type wfStep struct {
	line int
	uses string
	run  string
	with map[string]string
}

var (
	pwnRefRe       = regexp.MustCompile(pwnRefPattern)
	cacheActionRe  = regexp.MustCompile(`^actions/cache(/restore|/save)?@`)
	setupActionRe  = regexp.MustCompile(`^(actions/setup-(?:node|python|java|go|dotnet)|ruby/setup-ruby)@`)
	setupCachePMRe = regexp.MustCompile(`^(?:npm|yarn|pnpm|pip|pipenv|poetry|gradle|maven|sbt|bundler|true)$`)
	exprRe         = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	keyLineRe      = regexp.MustCompile(`^([A-Za-z_][\w-]*):[ \t]*(.*)$`)
	publishRunRe   = regexp.MustCompile(`(?:^|[\s;&|(])(?:(?:npm|pnpm|yarn)\s(?:[^\n|;&]*?\s)?publish(?:\s|$)|(?:changeset|lerna)\s+publish(?:\s|$)|twine\s+upload\b|poetry\s+publish\b|uv\s+publish\b|cargo\s+publish\b|gem\s+push\b|goreleaser\s+(?:release|r)\b|dotnet\s+nuget\s+push\b)`)
	publishUsesRe  = regexp.MustCompile(`^(?:pypa/gh-action-pypi-publish|goreleaser/goreleaser-action|JS-DevTools/npm-publish|rust-lang/crates-io-auth-action)@`)
	publishSecret  = regexp.MustCompile(`(?i)secrets\.([A-Z0-9_]*(?:NPM|PYPI|TWINE|CARGO_REGISTRY|CRATES_IO|RUBYGEMS|NUGET|PUBLISH|GPG|SIGNING|COSIGN)[A-Z0-9_]*)`)
	needsItemRe    = regexp.MustCompile(`[A-Za-z_][\w-]*`)
)

// extractCacheFacts reads one workflow for IAC-507. It reuses the workflow
// readers of pull_request_target.go (triggers, jobs, job conditions, the
// checkout test) and adds only a step reader.
func extractCacheFacts(path string, content []byte) *workflowCacheFacts {
	text := string(content)
	if !isWorkflowFile(path) || (!strings.Contains(text, "cache") && !strings.Contains(text, "setup-go")) {
		return nil
	}
	lines := strings.Split(text, "\n")
	events := workflowEvents(lines)
	if len(events) == 0 {
		return nil
	}
	jobs := workflowJobs(lines)
	facts := &workflowCacheFacts{path: path, events: events}
	trigger := firstOf(events, lowTrustWriters)
	wfMode := topLevelValue(lines, "cache-mode")
	wfPerms := permissionsBlock(lines, 0, len(lines), 0)

	// What each job can publish, so a restore can be tied to credentials by
	// `needs:`.
	names := make([]string, len(jobs))
	steps := make([][]wfStep, len(jobs))
	caps := make([]string, len(jobs))
	for i := range jobs {
		names[i] = jobName(lines, jobs[i])
		steps[i] = jobSteps(lines, jobs[i])
		caps[i] = publishCapability(lines, jobs[i], steps[i], wfPerms)
	}

	for i, j := range jobs {
		mode := jobValue(lines, j, "cache-mode")
		if mode == "" {
			mode = wfMode
		}
		entries := cacheEntries(steps[i])
		if len(entries) == 0 {
			continue
		}
		if trigger != "" && jobRunsForkCode(lines, j, events) && mode != "read" && mode != "none" {
			explicit := ""
			if mode == "write" || mode == "write-only" {
				explicit = mode
			}
			for _, e := range entries {
				if e.save {
					facts.writers = append(facts.writers, cacheWriter{cacheEntry: e, trigger: trigger, explicit: explicit})
				}
			}
		}
		if onlyPullRequestEvents(events) || mode == "none" || mode == "write-only" {
			continue
		}
		why := caps[i]
		if why == "" {
			why = needingCapability(jobs, names, lines, i, caps)
		}
		if why == "" {
			continue
		}
		for _, e := range entries {
			if e.restore {
				facts.restores = append(facts.restores, cacheRestore{cacheEntry: e, publishes: why})
			}
		}
	}
	if len(facts.writers) == 0 && len(facts.restores) == 0 {
		return nil
	}
	return facts
}

func isWorkflowFile(path string) bool {
	p := strings.ReplaceAll(path, "\\", "/")
	return (strings.HasPrefix(p, ghaWorkflowsPrefix) || strings.Contains(p, "/"+ghaWorkflowsPrefix)) &&
		(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
}

func firstOf(events, among []string) string {
	for _, a := range among {
		if containsString(events, a) {
			return a
		}
	}
	return ""
}

// jobRunsForkCode reports whether the job checks out the pull request's
// commit: IAC-505's test, on the same pattern and the same job exclusions.
// issue_comment has no exclusion check, since the condition that enables such a
// job (`github.event.issue.pull_request`) is not one that keeps it off.
func jobRunsForkCode(lines []string, j workflowJob, events []string) bool {
	if (containsString(events, "pull_request_target") || containsString(events, "workflow_run")) && j.excludesPrivileged(events) {
		return false
	}
	if gatedToTrustedPR(jobCondition(lines, j)) {
		return false
	}
	for ln := j.start; ln <= j.end && ln <= len(lines); ln++ {
		if pwnRefRe.MatchString(lines[ln-1]) && refFetchesCode(lines, ln) {
			return true
		}
	}
	return false
}

var (
	trustedMarkerRe = regexp.MustCompile(`github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository` +
		`|github\.event\.pull_request\.head\.repo\.fork\s*==\s*false` +
		`|github\.(?:actor|triggering_actor)\s*==\s*['"](?:dependabot|renovate)\[bot\]['"]` +
		`|github\.event\.pull_request\.user\.login\s*==\s*['"](?:dependabot|renovate)\[bot\]['"]` +
		`|github\.event\.workflow_run\.head_repository\.full_name\s*==\s*github\.repository` +
		`|github\.event\.pull_request\.merged\s*==\s*true`)
	otherEventRe = regexp.MustCompile(`github\.event_name\s*==\s*['"](?:push|workflow_dispatch|schedule|release)['"]`)
)

// gatedToTrustedPR reports whether a job condition lets a run through only for
// a pull request its own repository or a dependency bot opened, or one already
// merged: the cases where the head commit is not a stranger's code. Every
// `||` alternative must say so (or be another event entirely). A condition it
// cannot read, a label check and an author_association check included, gates
// nothing: those are a maintainer's decision about a stranger's code.
func gatedToTrustedPR(cond string) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return false
	}
	for _, alt := range strings.Split(cond, "||") {
		if !trustedMarkerRe.MatchString(alt) && !otherEventRe.MatchString(alt) {
			return false
		}
	}
	return true
}

// jobCondition returns the job's own `if:`, including a block or folded
// scalar spread over several lines.
func jobCondition(lines []string, j workflowJob) string {
	_, keyIndent := jobKeyIndents(lines, j)
	for ln := j.start + 1; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		if indentOf(l) != keyIndent {
			continue
		}
		m := keyLineRe.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 2 || m[1] != "if" {
			continue
		}
		parts := []string{strings.TrimSpace(stripYAMLComment(m[2]))}
		for c := ln; c < j.end && c < len(lines); c++ {
			t := strings.TrimSpace(lines[c])
			if t != "" && indentOf(lines[c]) <= keyIndent {
				break
			}
			if t != "" && !strings.HasPrefix(t, "#") {
				parts = append(parts, t)
			}
		}
		return strings.Trim(strings.Join(parts, " "), "|>- ")
	}
	return ""
}

// cacheEntries lists the cache restores and saves among a job's steps.
func cacheEntries(steps []wfStep) []cacheEntry {
	var out []cacheEntry
	for _, s := range steps {
		if m := cacheActionRe.FindStringSubmatch(s.uses); m != nil {
			e := cacheEntry{line: s.line, family: "actions/cache", key: unquoteScalar(s.with["key"]),
				save: m[1] != "/restore", restore: m[1] != "/save"}
			for _, rk := range strings.Split(s.with["restore-keys"], "\n") {
				if rk = unquoteScalar(strings.TrimSpace(rk)); rk != "" {
					e.restoreKeys = append(e.restoreKeys, rk)
				}
			}
			out = append(out, e)
			continue
		}
		m := setupActionRe.FindStringSubmatch(s.uses)
		if m == nil {
			continue
		}
		pm := unquoteScalar(s.with["cache"])
		switch {
		case m[1] == "actions/setup-go":
			// setup-go caches by default from v4; v1 to v3 have no cache.
			if pm == "false" || setupGoBeforeCaching(s.uses) {
				continue
			}
			pm = "go"
		case m[1] == "ruby/setup-ruby":
			if unquoteScalar(s.with["bundler-cache"]) != "true" {
				continue
			}
			pm = "bundler"
		case !setupCachePMRe.MatchString(pm):
			continue
		}
		out = append(out, cacheEntry{line: s.line, family: m[1], pm: pm, save: true, restore: true})
	}
	return out
}

var setupGoOldRe = regexp.MustCompile(`@v[123](?:[.\d]*)?$`)

// setupGoBeforeCaching reports a tag pin to a setup-go that predates its cache.
// A commit-SHA pin cannot be read and is taken to be recent.
func setupGoBeforeCaching(uses string) bool { return setupGoOldRe.MatchString(uses) }

func unquoteScalar(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

// jobSteps reads the steps of a job: each `- ` item under its `steps:` key,
// with its `uses:`, `run:` and `with:` values (block scalars joined by
// newlines). It reads only what IAC-507 needs.
func jobSteps(lines []string, j workflowJob) []wfStep {
	_, keyIndent := jobKeyIndents(lines, j)
	stepsAt := -1
	for ln := j.start + 1; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		if t := strings.TrimSpace(l); t != "" && indentOf(l) == keyIndent && strings.HasPrefix(t, "steps:") {
			stepsAt = ln
			break
		}
	}
	if stepsAt < 0 {
		return nil
	}
	var steps []wfStep
	dash := -1
	var cur []int
	flush := func() {
		if len(cur) > 0 {
			steps = append(steps, parseStep(lines, cur))
		}
		cur = nil
	}
	for ln := stepsAt + 1; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			if len(cur) > 0 {
				cur = append(cur, ln)
			}
			continue
		}
		ind := indentOf(l)
		if ind <= keyIndent && !strings.HasPrefix(t, "- ") {
			break
		}
		if strings.HasPrefix(t, "- ") && (dash < 0 || ind == dash) {
			if dash < 0 {
				dash = ind
			}
			flush()
		}
		cur = append(cur, ln)
	}
	flush()
	return steps
}

// jobKeyIndents returns the indent of the job's name and of its own keys.
func jobKeyIndents(lines []string, j workflowJob) (jobIndent, keyIndent int) {
	jobIndent = indentOf(lines[j.start-1])
	for k := j.start; k < len(lines) && k < j.end; k++ {
		if t := strings.TrimSpace(lines[k]); t != "" && !strings.HasPrefix(t, "#") {
			return jobIndent, indentOf(lines[k])
		}
	}
	return jobIndent, jobIndent + 2
}

func isBlockScalar(v string) bool {
	return strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">")
}

// parseStep reads one step given its line numbers (1-based).
func parseStep(lines []string, lns []int) wfStep {
	st := wfStep{line: lns[0], with: map[string]string{}}
	base, withIndent := -1, -1
	curKey := ""
	// block joins the lines after k that are indented deeper than minIndent.
	block := func(k, minIndent int) (string, int) {
		var b []string
		for k++; k < len(lns); k++ {
			l := lines[lns[k]-1]
			if strings.TrimSpace(l) != "" && indentOf(l) <= minIndent {
				break
			}
			b = append(b, strings.TrimSpace(l))
		}
		return strings.Join(b, "\n"), k - 1
	}
	for k := 0; k < len(lns); k++ {
		raw := lines[lns[k]-1]
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(raw)
		if k == 0 && strings.HasPrefix(t, "- ") {
			t = strings.TrimSpace(t[2:])
			ind += 2
		}
		if base < 0 {
			base = ind
		}
		m := keyLineRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		val := strings.TrimSpace(stripYAMLComment(m[2]))
		switch {
		case ind == base:
			curKey, withIndent = m[1], -1
			switch m[1] {
			case "uses":
				st.uses = unquoteScalar(val)
			case "run":
				if isBlockScalar(val) {
					st.run, k = block(k, base)
				} else {
					st.run = val
				}
			}
		case curKey == "with" && ind > base:
			if withIndent < 0 {
				withIndent = ind
			}
			if ind != withIndent {
				continue
			}
			if isBlockScalar(val) {
				st.with[m[1]], k = block(k, withIndent)
			} else {
				st.with[m[1]] = val
			}
		}
	}
	return st
}

// jobName returns the job's key, e.g. "release".
func jobName(lines []string, j workflowJob) string {
	if m := keyLineRe.FindStringSubmatch(strings.TrimSpace(lines[j.start-1])); m != nil {
		return m[1]
	}
	return ""
}

// jobValue returns the scalar value of one of the job's own keys.
func jobValue(lines []string, j workflowJob, key string) string {
	_, keyIndent := jobKeyIndents(lines, j)
	for ln := j.start + 1; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		if indentOf(l) == keyIndent {
			if m := keyLineRe.FindStringSubmatch(strings.TrimSpace(l)); len(m) > 1 && m[1] == key {
				return unquoteScalar(stripYAMLComment(m[2]))
			}
		}
	}
	return ""
}

// topLevelValue returns the scalar value of a column-zero key.
func topLevelValue(lines []string, key string) string {
	for _, l := range lines {
		if indentOf(l) == 0 {
			if m := keyLineRe.FindStringSubmatch(l); len(m) > 1 && m[1] == key {
				return unquoteScalar(stripYAMLComment(m[2]))
			}
		}
	}
	return ""
}

// permissionsBlock reads a `permissions:` key at keyIndent between the 0-based
// line offsets from and to, as a map; nil when the key is absent. A scalar
// (`read-all`, `write-all`) comes back as {"*": value}.
func permissionsBlock(lines []string, from, to, keyIndent int) map[string]string {
	for k := from; k < to && k < len(lines); k++ {
		l := lines[k]
		if indentOf(l) != keyIndent {
			continue
		}
		m := keyLineRe.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 2 || m[1] != "permissions" {
			continue
		}
		out := map[string]string{}
		if v := strings.TrimSpace(stripYAMLComment(m[2])); v != "" {
			out["*"] = v
			return out
		}
		for c := k + 1; c < to && c < len(lines); c++ {
			t := strings.TrimSpace(lines[c])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if indentOf(lines[c]) <= keyIndent {
				break
			}
			if cm := keyLineRe.FindStringSubmatch(t); cm != nil {
				out[cm[1]] = strings.TrimSpace(stripYAMLComment(cm[2]))
			}
		}
		return out
	}
	return nil
}

// publishCapability says what a job holds that can publish or release, or "".
// A job's own `permissions:` replaces the workflow's.
func publishCapability(lines []string, j workflowJob, steps []wfStep, wfPerms map[string]string) string {
	_, keyIndent := jobKeyIndents(lines, j)
	perms := permissionsBlock(lines, j.start, j.end, keyIndent)
	if perms == nil {
		perms = wfPerms
	}
	// id-token: write is not a publish by itself: Pages deploys, cloud logins and
	// claude-code-action all take it. It is named when the job also publishes.
	oidcNote := ""
	if perms["id-token"] == "write" {
		oidcNote = " (the job has id-token: write)"
	}
	for _, s := range steps {
		if publishUsesRe.MatchString(s.uses) {
			return "uses " + strings.SplitN(s.uses, "@", 2)[0] + oidcNote
		}
		if strings.HasPrefix(s.uses, "changesets/action@") && s.with["publish"] != "" {
			return "uses changesets/action with publish" + oidcNote
		}
		for _, rl := range strings.Split(s.run, "\n") {
			if strings.HasPrefix(strings.TrimSpace(rl), "#") {
				continue
			}
			if m := publishRunRe.FindString(rl); m != "" {
				return "runs `" + strings.TrimSpace(m) + "`" + oidcNote
			}
		}
	}
	for ln := j.start; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if m := publishSecret.FindStringSubmatch(stripYAMLComment(l)); m != nil {
			return "secrets." + m[1] + oidcNote
		}
	}
	return ""
}

// needingCapability returns the capability of a job that (transitively) needs
// job i, since what i builds and restores flows into it.
func needingCapability(jobs []workflowJob, names, lines []string, i int, caps []string) string {
	reach := map[int]bool{i: true}
	for changed := true; changed; {
		changed = false
		for k := range jobs {
			if reach[k] {
				continue
			}
			for _, n := range jobNeeds(lines, jobs[k]) {
				for r := range reach {
					if names[r] == n && !reach[k] {
						reach[k], changed = true, true
					}
				}
			}
		}
	}
	idx := make([]int, 0, len(reach))
	for k := range reach {
		if k != i {
			idx = append(idx, k)
		}
	}
	sort.Ints(idx)
	for _, k := range idx {
		if caps[k] != "" {
			return caps[k] + " in job " + names[k] + ", which needs this one"
		}
	}
	return ""
}

// jobNeeds reads `needs:` in its scalar, flow-list and block-list forms.
func jobNeeds(lines []string, j workflowJob) []string {
	_, keyIndent := jobKeyIndents(lines, j)
	for ln := j.start + 1; ln <= j.end && ln <= len(lines); ln++ {
		l := lines[ln-1]
		if indentOf(l) != keyIndent {
			continue
		}
		m := keyLineRe.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 2 || m[1] != "needs" {
			continue
		}
		if v := strings.TrimSpace(stripYAMLComment(m[2])); v != "" {
			return needsItemRe.FindAllString(strings.Trim(v, "[]"), -1)
		}
		var out []string
		for c := ln; c < j.end && c < len(lines); c++ {
			t := strings.TrimSpace(lines[c])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if indentOf(lines[c]) <= keyIndent || !strings.HasPrefix(t, "- ") {
				break
			}
			out = append(out, unquoteScalar(stripYAMLComment(t[2:])))
		}
		return out
	}
	return nil
}

// keyTok is one position of a cache key pattern: a literal rune, or a wildcard
// standing for a `${{ … }}` expression.
type keyTok struct {
	r    rune
	star bool
}

// parseKeyGlob turns a cache key into a pattern, each expression a wildcard.
func parseKeyGlob(key string) []keyTok {
	var out []keyTok
	rest := key
	for rest != "" {
		loc := exprRe.FindStringIndex(rest)
		if loc == nil {
			loc = []int{len(rest), len(rest)}
		}
		for _, r := range rest[:loc[0]] {
			out = append(out, keyTok{r: r})
		}
		if loc[1] > loc[0] {
			out = append(out, keyTok{star: true})
		}
		rest = rest[loc[1]:]
	}
	return out
}

// globsIntersect reports whether some string matches both patterns.
func globsIntersect(a, b []keyTok) bool {
	memo := map[[2]int]bool{}
	var f func(i, j int) bool
	f = func(i, j int) bool {
		if i == len(a) && j == len(b) {
			return true
		}
		k := [2]int{i, j}
		if v, ok := memo[k]; ok {
			return v
		}
		memo[k] = false // breaks the cycle of two stars
		res := false
		switch {
		case i < len(a) && a[i].star:
			res = f(i+1, j) || (j < len(b) && f(i, j+1))
		case j < len(b) && b[j].star:
			res = f(i, j+1) || (i < len(a) && f(i+1, j))
		case i < len(a) && j < len(b):
			res = a[i].r == b[j].r && f(i+1, j+1)
		}
		memo[k] = res
		return res
	}
	return f(0, 0)
}

// longestLiteral is the longest run of literal characters in a pattern.
func longestLiteral(p []keyTok) int {
	best, cur := 0, 0
	for _, t := range p {
		if t.star {
			cur = 0
			continue
		}
		cur++
		if cur > best {
			best = cur
		}
	}
	return best
}

// minMeaningfulLiteral is how long a literal the restoring pattern must carry.
// A key that is all expressions, or `${{ runner.os }}-` against anything, would
// otherwise "match" every cache in the repository.
const minMeaningfulLiteral = 4

// cachesMeet reports whether a cache saved as w can be the one restored as r,
// and says what matched. Expressions are wildcards, which can only over-match,
// so a match needs a literal run of at least minMeaningfulLiteral characters in
// the restoring pattern.
func cachesMeet(w cacheWriter, r cacheRestore) (string, bool) {
	if w.family != r.family {
		return "", false
	}
	if w.family != "actions/cache" {
		if w.pm != r.pm {
			return "", false
		}
		return fmt.Sprintf("both use %s's own cache for %s", w.family, w.pm), true
	}
	if w.key == "" {
		return "", false
	}
	wk := parseKeyGlob(w.key)
	if rk := parseKeyGlob(r.key); r.key != "" && longestLiteral(rk) >= minMeaningfulLiteral && globsIntersect(wk, rk) {
		return fmt.Sprintf("the saved key %q can equal the restored key %q", w.key, r.key), true
	}
	for _, p := range r.restoreKeys {
		pk := append(parseKeyGlob(p), keyTok{star: true})
		if longestLiteral(pk) >= minMeaningfulLiteral && globsIntersect(wk, pk) {
			return fmt.Sprintf("the saved key %q starts with the restore-keys prefix %q", w.key, p), true
		}
	}
	return "", false
}

// crossWorkflowCachePoisoning pairs each restore in a publishing job with a
// writer in a different workflow, and reports it on the restore step. One
// finding per restore, naming the first writer in path order.
func crossWorkflowCachePoisoning(all []*workflowCacheFacts) []findings.Finding {
	var facts []*workflowCacheFacts
	for _, f := range all {
		if f != nil {
			facts = append(facts, f)
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].path < facts[j].path })
	var out []findings.Finding
	for _, b := range facts {
		for _, r := range b.restores {
			var writer *cacheWriter
			var writerPath, matched string
			others := 0
			for _, a := range facts {
				if a.path == b.path {
					continue
				}
				for i := range a.writers {
					m, ok := cachesMeet(a.writers[i], r)
					if !ok {
						continue
					}
					if writer == nil {
						writer, writerPath, matched = &a.writers[i], a.path, m
					} else {
						others++
					}
				}
			}
			if writer == nil {
				continue
			}
			out = append(out, cachePoisoningFinding(b.path, r, writer, writerPath, matched, others))
		}
	}
	return out
}

func cachePoisoningFinding(path string, r cacheRestore, w *cacheWriter, writerPath, matched string, others int) findings.Finding {
	conf := findings.ConfidenceLow
	scope := fmt.Sprintf("%s runs on %s, which GitHub now gives read-only cache access by default; "+
		"the write lands only where cache-mode is write or write-only, or on a platform without that restriction",
		writerPath, w.trigger)
	if w.explicit != "" {
		conf = findings.ConfidenceHigh
		scope = fmt.Sprintf("%s runs on %s and sets cache-mode: %s", writerPath, w.trigger, w.explicit)
	}
	more := ""
	if others > 0 {
		more = fmt.Sprintf(" (%d more writer(s) match)", others)
	}
	return findings.Finding{
		RuleID:     crossWorkflowCacheRuleID,
		Severity:   findings.SeverityHigh,
		Confidence: conf,
		Message: fmt.Sprintf("This job restores a cache that %s:%d can write after checking out the pull request's code%s: %s. "+
			"Matched because %s (expressions are treated as wildcards). The restoring job can publish: %s. "+
			"A fork's code that poisons the cache runs here with those credentials.",
			writerPath, w.line, more, scope, matched, r.publishes),
		Location: findings.Location{FilePath: path, StartLine: r.line, EndLine: r.line},
		Metadata: map[string]string{
			"cwe":         "CWE-345",
			"writer":      fmt.Sprintf("%s:%d", writerPath, w.line),
			"writer_when": w.trigger,
			"matched":     matched,
			"publishes":   r.publishes,
		},
	}
}
