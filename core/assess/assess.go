// Package assess turns a finished scan into an assessment a first-time user
// can act on: the issues grouped by the action that resolves them, what was
// and was not checked, what nox could not settle statically, and the next
// command to run.
//
// It is presentation over data nox already has. Every line is derived from the
// scan result, the shared fix planner (core/fix) and the shared hypothesis
// builder (core/hypothesize); nothing here decides anything those do not, and
// nothing here changes a machine output. It sits above core for the same
// reason core/hypothesize does: core must not be able to reach core/attack.
//
// One implementation so the CLI, the MCP server and the LSP cannot drift into
// three different stories about the same scan.
package assess

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
	"github.com/nox-hq/nox/core/hypothesize"
	"github.com/nox-hq/nox/core/plugincap"
	"github.com/nox-hq/nox/core/rules"
)

// Input is everything an assessment is built from. Plain data, so the builder
// can be tested without running a scan.
type Input struct {
	// Findings are the findings the caller reports on: active, and already
	// narrowed by any severity or confidence threshold the user asked for.
	Findings []findings.Finding
	// Rules resolves a rule ID to its description for issue titles. Optional.
	Rules *rules.RuleSet
	// Plan is the attack plan built from the same scan. Optional; nil means no
	// verification section.
	Plan *attack.Plan
	// Scope is what the scan looked at.
	Scope nox.ScopeSet
	// Degradations are the parts of the scan that did not run.
	Degradations []nox.Degradation
	// Packages is the number of dependencies inventoried.
	Packages int
	// Targets, when set, is asked what each planned upgrade target is still
	// vulnerable to, so the upgrade names a version that clears every known
	// advisory. Optional; nil plans from the findings alone.
	Targets fix.Checker
	// Offline is set when the scan made no network calls, so known
	// vulnerabilities in dependencies were not looked up.
	Offline bool
	// Target is the scanned path, as the user typed it.
	Target string
	// FindingsPath is where findings.json was written, or "" when this run
	// did not write one. Commands that read it are only offered when it exists.
	FindingsPath string
	// InventoryPath is where ai.inventory.json was written, or "" when it was
	// not. `nox attack plan` needs it for the agent-tool scenarios.
	InventoryPath string
	// Leads are things the scan holds worth testing that are not findings
	// (nox.ScanResult.Leads). Never counted as issues.
	Leads []nox.Lead
	// LeadChecks are the coverage words for the checks that produce leads
	// (nox.ScanResult.LeadChecks).
	LeadChecks []string
}

// FromScan assembles an Input from a scan result. active is the finding list
// the caller reports on (see Input.Findings).
func FromScan(r *nox.ScanResult, active []findings.Finding, target, findingsPath string, offline bool) Input {
	in := Input{
		Findings:     active,
		Target:       target,
		FindingsPath: findingsPath,
		Offline:      offline,
	}
	if r == nil {
		return in
	}
	in.Rules = r.Rules
	in.Scope = r.Scope
	in.Leads = r.Leads
	in.LeadChecks = r.LeadChecks
	in.Degradations = r.Degradations
	if r.Inventory != nil {
		in.Packages = len(r.Inventory.Packages())
	}
	// The same builder `nox attack plan` and --emit-hypotheses use. An empty
	// timestamp: the assessment reads hypotheses, never the plan's date, and a
	// clock read here would make the output differ between identical runs.
	if plan, err := hypothesize.From(r, target, ""); err == nil {
		in.Plan = plan
	}
	return in
}

// Issue is one thing to do, standing for every finding it resolves.
type Issue struct {
	// Kind says what sort of action resolves it.
	Kind IssueKind
	// Summary is the one-line statement of the issue and its resolution.
	Summary string
	// Severity is the highest severity among the findings it stands for.
	Severity findings.Severity
	// Confidence is the highest confidence among those findings.
	Confidence findings.Confidence
	// Findings is how many findings it stands for.
	Findings int
	// Fingerprints are the findings it stands for, in the scan's order. It lets
	// a caller that acts on the issue (core/remediate) name exactly what the
	// action is meant to clear, and later look for exactly that.
	Fingerprints []string
	// RuleID is the rule the findings share, for a code issue.
	RuleID string
	// Upgrade is the move that resolves a KindUpgrade or KindMajorUpgrade
	// issue, the same action `nox fix` applies.
	Upgrade *fix.UpgradeAction
	// FixedIn is the best fixed version known for a KindNoFix issue, "" when
	// none is published.
	FixedIn string
	// VulnClass is the taint class a code issue shares, "" otherwise.
	VulnClass string
	// Ecosystem, Package and Version name the dependency of a KindNoFix issue,
	// so the plan can say why nox could not move it.
	Ecosystem, Package, Version string
	// Attention is set when the issue needs a person's attention now, as
	// opposed to being a lower-priority observation. See NeedsAttention.
	Attention bool
	rank      int
}

// NeedsAttention is the one definition of "needs attention", shared by the
// assessment headline and the fix plan. A finding needs attention when it is
// critical or high severity (the same line `nox ci-gate` draws for a build),
// or medium severity that the analyzer is highly confident about. Everything
// else (a medium the analyzer is unsure of, any low or unrated finding) is a
// lower-priority observation: it stays in findings.json and SARIF and in the
// verbose listing, it just is not counted as something to act on today.
//
// The rule uses each finding's own severity and confidence, never the worst of
// one and the best of the other across a group, so a group is not promoted by
// a critical that is a guess plus an unrelated medium that is certain.
func NeedsAttention(s findings.Severity, c findings.Confidence) bool {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return true
	case findings.SeverityMedium:
		return c == findings.ConfidenceHigh
	}
	return false
}

// anyAttention reports whether any finding at idx needs attention.
func anyAttention(ff []findings.Finding, idx []int) bool {
	for _, i := range idx {
		if NeedsAttention(ff[i].Severity, ff[i].Confidence) {
			return true
		}
	}
	return false
}

// IssueKind classifies an issue by what resolves it.
type IssueKind string

// Issue kinds.
const (
	// KindUpgrade is resolved by one dependency upgrade `nox fix` would apply.
	KindUpgrade IssueKind = "upgrade"
	// KindMajorUpgrade is resolved by an upgrade `nox fix` holds back because it
	// crosses a major version.
	KindMajorUpgrade IssueKind = "major_upgrade"
	// KindNoFix is a vulnerable dependency with no upgrade nox can apply.
	KindNoFix IssueKind = "no_fix"
	// KindCode is resolved by a change to the project's own files.
	KindCode IssueKind = "code"
)

// Verification is a lead nox cannot settle statically, and the hypotheses it
// would test.
type Verification struct {
	// Where names the code or component the hypotheses are grounded in.
	Where string
	// Hypotheses is how many attack hypotheses the plan holds for it.
	Hypotheses int
	// Scenarios are the scenario IDs, sorted.
	Scenarios []string
	// Objective is what the first hypothesis would try to achieve.
	Objective string
}

// Limit is something nox did not check or could not complete.
type Limit struct {
	// Summary says, in plain words, what was not checked.
	Summary string
	// Action is the one thing that enables it, or "" when there is none.
	Action string
	// Blocking is set when a check failed rather than being left disabled.
	Blocking bool
}

// Report is a built assessment.
type Report struct {
	// Issues are sorted most important first.
	Issues []Issue
	// FindingCount is how many findings the issues stand for in total.
	FindingCount int
	// AttentionIssues and AttentionFindings count the issues that need
	// attention (Issue.Attention) and the findings they stand for. The rest of
	// Issues are lower-priority observations; nothing is dropped from Issues.
	AttentionIssues   int
	AttentionFindings int
	// Checked names each concern the scan covered.
	Checked []string
	// NotChecked lists what the scan did not cover, and how to enable it.
	NotChecked []Limit
	// Undetermined states what the static scan could not settle.
	Undetermined []string
	// Verify lists leads that need a runtime test.
	Verify []Verification
	// Leads are scan leads that need a manual test, in the scan's order
	// (sorted by file and line).
	Leads []nox.Lead
	// NextSteps are commands, most useful first.
	NextSteps []string
}

// Build derives an assessment from in. Deterministic: same input, same report.
func Build(in Input) Report {
	r := Report{FindingCount: len(in.Findings)}
	r.Issues = issues(in)
	for _, is := range r.Issues {
		if is.Attention {
			r.AttentionIssues++
			r.AttentionFindings += is.Findings
		}
	}
	r.Checked, r.NotChecked = coverage(in)
	r.Undetermined = undetermined(in.Findings)
	r.Verify = verifications(in)
	r.Leads = in.Leads
	r.NextSteps = nextSteps(in, r)
	return r
}

func issues(in Input) []Issue {
	ff := in.Findings
	// The planner `nox fix` applies and the MCP fix_plan tool shows. The
	// assessment's upgrade lines are exactly its actions, so "upgrade axios"
	// here is the command `nox fix --dry-run` prints next.
	plan := fix.PlanUpgrades(ff, fix.Options{Checker: in.checker()})
	used := make([]bool, len(ff))

	var out []Issue
	for _, a := range plan.Actions {
		out = append(out, upgradeIssue(KindUpgrade, a, ff, used))
	}
	for _, a := range plan.Held {
		out = append(out, upgradeIssue(KindMajorUpgrade, a, ff, used))
	}
	out = append(out, noFixIssues(plan.Unplanned, ff, used)...)
	out = append(out, codeIssues(in, used)...)

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Attention != b.Attention {
			return a.Attention
		}
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		if sa, sb := severityWeight(a.Severity), severityWeight(b.Severity); sa != sb {
			return sa > sb
		}
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		return a.Summary < b.Summary
	})
	return out
}

func fingerprints(ff []findings.Finding, idx []int) []string {
	out := make([]string, len(idx))
	for j, i := range idx {
		out[j] = ff[i].Fingerprint
	}
	return out
}

// worst returns the highest severity and confidence over the findings at idx,
// and marks them used.
func worst(ff []findings.Finding, idx []int, used []bool) (findings.Severity, findings.Confidence) {
	var sev findings.Severity
	var conf findings.Confidence
	for _, i := range idx {
		used[i] = true
		if severityWeight(ff[i].Severity) > severityWeight(sev) {
			sev = ff[i].Severity
		}
		if confidenceWeight(ff[i].Confidence) > confidenceWeight(conf) {
			conf = ff[i].Confidence
		}
	}
	return sev, conf
}

// MajorNote is what a major-version upgrade's summary adds to the usual line.
// core/remediate trims it to state the same fact in its own words.
const MajorNote = " A major version, so check for breaking changes; nox fix apply --include-major applies it."

func upgradeIssue(kind IssueKind, a fix.UpgradeAction, ff []findings.Finding, used []bool) Issue {
	sev, conf := worst(ff, a.Findings, used)
	from := a.From
	if from == "" {
		from = "the installed version"
	}
	s := fmt.Sprintf("Upgrade %s %s -> %s%s: fixes %s (highest severity: %s).",
		a.Package, from, a.To, inDir(a.Manifest),
		plural(len(a.Findings), "known vulnerability", "known vulnerabilities"), sev)
	if kind == KindMajorUpgrade {
		s += MajorNote
	}
	s += targetNote(a)
	up := a
	return Issue{Kind: kind, Summary: s, Severity: sev, Confidence: conf, Findings: len(a.Findings),
		Fingerprints: fingerprints(ff, a.Findings), Upgrade: &up, rank: rank(sev, conf),
		Attention: anyAttention(ff, a.Findings)}
}

// checker is Targets unless the scan was offline, whose plan must not reach
// the network either.
func (in Input) checker() fix.Checker {
	if in.Offline {
		return nil
	}
	return in.Targets
}

// targetNote says what the planner learned about the target beyond the
// findings: advisories that would remain, or that it could not check.
func targetNote(a fix.UpgradeAction) string {
	ids := strings.Join(a.Remaining, ", ")
	switch {
	case a.PolicyTarget != "":
		return fmt.Sprintf(" No version inside the upgrade policy clears every advisory: %s would still be affected by %s; only %s does, and it needs --include-major.",
			a.PolicyTarget, ids, a.To)
	case len(a.Remaining) > 0:
		return fmt.Sprintf(" Still affected after this upgrade, with no fix published: %s.", ids)
	case a.Unverified:
		return " Not checked against the advisory database: advisories introduced after the installed version may still affect the target."
	}
	return ""
}

// inDir names the manifest's directory when it is not the scan root, so a
// monorepo reader knows which workspace an upgrade belongs to.
func inDir(manifest string) string {
	if dir := path.Dir(manifest); manifest != "" && dir != "." {
		return " in " + dir
	}
	return ""
}

// noFixIssues groups the dependency findings no upgrade resolves, one issue per
// package version, because that is the unit someone has to decide about.
func noFixIssues(unplanned []int, ff []findings.Finding, used []bool) []Issue {
	type key struct{ manifest, eco, pkg, version string }
	groups := map[key][]int{}
	var order []key
	for _, i := range unplanned {
		m := ff[i].Metadata
		k := key{ff[i].Location.FilePath, m["ecosystem"], m["package"], m["version"]}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	out := make([]Issue, 0, len(order))
	for _, k := range order {
		idx := groups[k]
		sev, conf := worst(ff, idx, used)
		name := k.pkg
		if name == "" {
			name = "A dependency"
		}
		if k.version != "" {
			name += " " + k.version
		}
		var fixes []string
		for _, i := range idx {
			if f := ff[i].Metadata["fixed_in"]; f != "" {
				fixes = append(fixes, f)
			}
		}
		vulns := plural(len(idx), "known vulnerability", "known vulnerabilities")
		var s string
		if best := fix.BestFix(fixes); best != "" {
			// A fix exists; nox fix cannot apply it (an ecosystem it does not
			// drive, or a version it will not move to automatically).
			s = fmt.Sprintf("Upgrade %s to %s or later%s yourself: fixes %s (highest severity: %s); nox fix cannot apply this upgrade.",
				name, best, inDir(k.manifest), vulns, sev)
		} else {
			s = fmt.Sprintf("%s%s has %s with no fixed version published (highest severity: %s). "+
				"Check the advisories for a workaround, or replace the package.",
				name, inDir(k.manifest), vulns, sev)
		}
		out = append(out, Issue{Kind: KindNoFix, Summary: s, Severity: sev, Confidence: conf, Findings: len(idx),
			Fingerprints: fingerprints(ff, idx), FixedIn: fix.BestFix(fixes), rank: rank(sev, conf),
			Ecosystem: k.eco, Package: k.pkg, Version: k.version,
			Attention: anyAttention(ff, idx)})
	}
	return out
}

// codeIssues groups every remaining finding by its rule (and, for taint, by
// vulnerability class), since one rule is one kind of change.
func codeIssues(in Input, used []bool) []Issue {
	ff := in.Findings
	type key struct{ rule, class string }
	groups := map[key][]int{}
	var order []key
	for i := range ff {
		if used[i] {
			continue
		}
		k := key{ff[i].RuleID, ff[i].Metadata["vuln_class"]}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	out := make([]Issue, 0, len(order))
	for _, k := range order {
		idx := groups[k]
		sev, conf := worst(ff, idx, used)
		group := make([]findings.Finding, len(idx))
		for j, i := range idx {
			group[j] = ff[i]
		}
		title := issueTitle(in.Rules, group, k.class)
		s := fmt.Sprintf("%s %s (%s severity, %s confidence).",
			title, where(ff, idx), severityOrUnrated(sev), confidenceOrUnknown(conf))
		out = append(out, Issue{Kind: KindCode, Summary: s, Severity: sev, Confidence: conf, Findings: len(idx),
			Fingerprints: fingerprints(ff, idx), RuleID: k.rule, VulnClass: k.class, rank: rank(sev, conf),
			Attention: anyAttention(ff, idx)})
	}
	return out
}

// classPhrases says what a taint flow means in words a reader without the CWE
// list can act on. A class missing here falls back to its name.
var classPhrases = map[string]string{
	"command_injection":      "Untrusted input reaches a shell command (command injection)",
	"sql_injection":          "Untrusted input reaches a database query (SQL injection)",
	"code_injection":         "Untrusted input reaches code evaluation (code injection)",
	"xss":                    "Untrusted input is written into a page (cross-site scripting)",
	"ssti":                   "Untrusted input reaches a template engine (template injection)",
	"path_traversal":         "Untrusted input chooses a file path (path traversal)",
	"ssrf":                   "Untrusted input chooses a URL the server fetches (SSRF)",
	"unsafe_deserialization": "Untrusted input is deserialized (unsafe deserialization)",
	"prompt_injection":       "Untrusted input reaches an LLM prompt (prompt injection)",
	"open_redirect":          "Untrusted input chooses a redirect target (open redirect)",
	"xpath_injection":        "Untrusted input reaches an XPath query (XPath injection)",
	"ldap_injection":         "Untrusted input reaches an LDAP query (LDAP injection)",
	"xxe":                    "Untrusted XML is parsed with external entities enabled (XXE)",
	"trust_boundary":         "Untrusted input crosses a trust boundary unchecked",
}

const maxTitle = 90

// issueTitle names a group of findings: the taint class in words, else the
// rule's own description, else the message the group's findings share.
func issueTitle(rs *rules.RuleSet, group []findings.Finding, class string) string {
	f := group[0]
	if class != "" {
		if p, ok := classPhrases[class]; ok {
			return p
		}
		return "Untrusted input reaches a " + strings.ReplaceAll(class, "_", " ") + " sink"
	}
	if rs != nil {
		if r, ok := rs.ByID(f.RuleID); ok && strings.TrimSpace(r.Description) != "" {
			return truncate(sentence(r.Description), maxTitle) + " [" + f.RuleID + "]"
		}
	}
	return truncate(sharedMessage(group), maxTitle) + " [" + f.RuleID + "]"
}

// sharedMessage is what every message in the group says. One finding's message
// names one package or one file, and titling a group with it would claim the
// rest say the same, so a group whose messages differ is titled by the clause
// they share before a colon ("Possible typosquatting"), else by the family.
func sharedMessage(group []findings.Finding) string {
	first := sentence(group[0].Message)
	same, lead := true, leadClause(first)
	for i := range group[1:] {
		m := sentence(group[i+1].Message)
		if m != first {
			same = false
		}
		if leadClause(m) != lead {
			lead = ""
		}
	}
	switch {
	case same && first != "":
		return first
	case lead != "":
		return lead
	}
	return catalog.Family(group[0].RuleID).Label + " finding"
}

func leadClause(s string) string {
	if i := strings.Index(s, ": "); i > 0 {
		return s[:i]
	}
	return ""
}

// where lists up to three places, as file:line or, for a dependency finding,
// as package@version: a lockfile line names nothing a reader can open.
func where(ff []findings.Finding, idx []int) string {
	seen := map[string]bool{}
	var places []string
	for _, i := range idx {
		p := place(ff[i])
		if !seen[p] {
			seen[p] = true
			places = append(places, p)
		}
	}
	sort.Strings(places)
	const shown = 3
	if len(places) <= shown {
		return "at " + strings.Join(places, ", ")
	}
	return fmt.Sprintf("in %d places, e.g. %s, and %d more",
		len(places), strings.Join(places[:shown], ", "), len(places)-shown)
}

func place(f findings.Finding) string {
	if pkg := f.Metadata["package"]; pkg != "" {
		if v := f.Metadata["version"]; v != "" {
			return pkg + "@" + v
		}
		return pkg
	}
	if f.Location.StartLine > 0 {
		return f.Location.FilePath + ":" + strconv.Itoa(f.Location.StartLine)
	}
	return f.Location.FilePath
}

// scopeLabels names each scope for a reader who has not read the docs.
var scopeLabels = map[nox.Scope]string{
	nox.ScopeSecrets:     "secrets",
	nox.ScopeCode:        "application code",
	nox.ScopeDeps:        "dependencies",
	nox.ScopeIaC:         "infrastructure configuration",
	nox.ScopeAI:          "AI integrations",
	nox.ScopeData:        "sensitive-data handling",
	nox.ScopeSupplyChain: "supply chain",
}

func coverage(in Input) (checked []string, notChecked []Limit) {
	for _, s := range in.Scope.Ran() {
		label := scopeLabels[s]
		if label == "" {
			label = string(s)
		}
		if s == nox.ScopeDeps {
			// "0 packages" reads like "0 vulnerable packages"; the honest
			// statement is that there was nothing to check.
			label = "dependencies (none found)"
			switch {
			case in.Packages > 0:
				label = fmt.Sprintf("dependencies (%s)", plural(in.Packages, "package", "packages"))
			case hasKind(in.Degradations, "lockfile_parse"):
				// Something declared dependencies and none could be resolved.
				// "none found" would say the opposite.
				label = "dependencies (declared, but none could be resolved)"
			}
		}
		checked = append(checked, label)
	}
	// A lead check says what it read and that it yields leads, never that
	// it checked: "authorization (Express, Fastify, Flask, FastAPI routes; leads only)".
	checked = append(checked, in.LeadChecks...)
	for _, s := range in.Scope.Skipped() {
		label := scopeLabels[s]
		if label == "" {
			label = string(s)
		}
		notChecked = append(notChecked, Limit{
			Summary: label + ": excluded by --only/--skip on this run.",
			Action:  "run without --only/--skip to include it",
		})
	}
	if in.Offline && in.Scope.Has(nox.ScopeDeps) {
		notChecked = append(notChecked, Limit{
			Summary: "Known vulnerabilities in dependencies: not looked up, because the scan ran offline.",
			Action:  "run without --offline to look them up",
		})
	}
	notChecked = append(notChecked, degradationLimits(in.Degradations)...)
	return checked, notChecked
}

func hasKind(ds []nox.Degradation, kind string) bool {
	for _, d := range ds {
		if string(d.Kind) == kind {
			return true
		}
	}
	return false
}

// kindHeadlines says what each kind of degradation leaves unchecked, in plain
// words. The producer's Impact text follows it; its Detail, which names
// plugins, files and errors, stays behind --verbose.
var kindHeadlines = map[string]string{
	"osv_lookup":         "Known-vulnerability lookup for dependencies did not complete",
	"advisory_detail":    "Some dependency severities could not be fetched; a severity gate may not see them",
	"lockfile_parse":     "Some dependency lockfiles could not be read",
	"vuln_data_load":     "Vulnerability data could not be loaded",
	"plugin":             "Some plugin checks did not run",
	"generated_report":   "Reports nox wrote itself were not scanned",
	"baseline":           "The baseline could not be applied",
	"suppression":        "Some suppressions could not be applied",
	"slop_feed":          "The package-hallucination feed was unavailable",
	"config":             "Part of .nox.yaml is not in effect",
	"mcp":                "Some MCP configuration checks did not complete",
	"intel_suppression":  "NOX Intelligence suppressions could not be applied",
	"intel_unverified":   "Some NOX Intelligence answers could not be verified",
	"intel_unreachable":  "NOX Intelligence could not be reached",
	"intel_incomplete":   "NOX Intelligence answered some packages only in part",
	"intel_contribution": "Observations could not be contributed to NOX Intelligence",
}

// degradationLimits collapses degradations into one line per kind and
// blocking-ness. An advisory plugin entry is a check the project did not enable,
// which a beginner needs to hear as "not enabled", not as "failed".
func degradationLimits(ds []nox.Degradation) []Limit {
	type key struct {
		kind     string
		blocking bool
	}
	groups := map[key][]nox.Degradation{}
	var order []key
	for _, d := range ds {
		k := key{string(d.Kind), d.Blocks()}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], d)
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].blocking != order[j].blocking {
			return order[i].blocking
		}
		return order[i].kind < order[j].kind
	})
	out := make([]Limit, 0, len(order))
	for _, k := range order {
		g := groups[k]
		if k.kind == "plugin" && !k.blocking {
			out = append(out, optionalChecks(g)...)
			continue
		}
		if k.kind == string(degrade.IntelIncomplete) {
			var mirror, rest []nox.Degradation
			for _, d := range g {
				if strings.Contains(d.Detail, osvsource.MirrorOnlyNote) {
					mirror = append(mirror, d)
				} else {
					rest = append(rest, d)
				}
			}
			if len(mirror) > 0 {
				// A specific statement, not the generic partial-answer line:
				// the cause is known and so is what it costs.
				out = append(out, Limit{
					Summary:  "Answered from NOX Intelligence's mirror; live OSV unavailable: advisories published or changed since the mirror last synced may be missing.",
					Action:   "re-run when OSV is reachable for a complete answer",
					Blocking: k.blocking,
				})
			}
			if len(rest) == 0 {
				continue
			}
			g = rest
		}
		head := kindHeadlines[k.kind]
		if k.kind == "lockfile_parse" && !k.blocking {
			// Advisory, not a failure: a package.json with no lockfile beside
			// it was read, but only as far as a manifest can be.
			head = "No lockfile is committed beside a package.json"
		}
		if head == "" {
			head = "A check did not complete (" + k.kind + ")"
		}
		if len(g) > 1 {
			head += fmt.Sprintf(" (%d entries)", len(g))
		}
		// No Action: what fixes a failed lookup or an unreadable lockfile is in
		// the Detail, which the [degraded] lines print in full.
		out = append(out, Limit{
			Summary:  head + ": " + sentence(g[0].Impact) + ".",
			Blocking: k.blocking,
		})
	}
	return out
}

// optionalChecks says, in capabilities, what installed-but-undeclared plugins
// would have checked. The reader should not need to know what a plugin is, let
// alone which one does what, so no plugin name appears here; the names stay in
// the degradation's Detail (findings.json, --verbose).
//
// Only a gap is worth a line. A plugin whose check core already performs
// (container configuration), one measured to hurt (reachability, which turns a
// transitive dependency into "likely false positive"), and one that annotates
// rather than checks leave nothing unchecked, so naming them under "Not
// checked" would send the reader to enable something that duplicates or harms.
// They remain accounted for: the full list is in the degradation itself.
//
// A detail this package cannot read (a producer other than the CLI) falls back
// to the generic line rather than to silence.
func optionalChecks(g []nox.Degradation) []Limit {
	var names []string
	for _, d := range g {
		n, ok := plugincap.Undeclared(d.Detail)
		if !ok {
			return []Limit{{
				Summary: "Optional checks are installed but not enabled for this project, so they did not run.",
				Action:  "run nox enable --list to see them and nox enable <name> to turn one on (writes .nox.yaml)",
			}}
		}
		names = append(names, n...)
	}
	var out []Limit
	if opt := plugincap.Capabilities(names, plugincap.Optional); len(opt) > 0 {
		out = append(out, Limit{
			Summary: "Optional checks are installed but not enabled, so they did not run: " + plugincap.Join(opt) + ".",
			Action:  enableAction(plugincap.Slugs(names)),
		})
	}
	if live := plugincap.Capabilities(names, plugincap.Live); len(live) > 0 {
		out = append(out, Limit{
			Summary: "Live testing did not run (" + plugincap.Join(live) + "): it sends traffic to, or reads, a running system, so it needs your explicit go-ahead.",
			Action:  "plan it with nox attack plan; nothing is sent until you add --authorize",
		})
	}
	return out
}

// enableAction is the one command that turns the listed checks on. It names
// capabilities, never plugins: `nox enable` resolves them and writes .nox.yaml.
func enableAction(slugs []string) string {
	if len(slugs) == 0 {
		return "run nox enable --list to see them and nox enable <name> to turn one on (writes .nox.yaml)"
	}
	return "run nox enable " + strings.Join(slugs, " ") + " (writes .nox.yaml; nox enable --list says what each checks)"
}

// undetermined states what the static scan left open, from the fields the
// findings themselves carry.
func undetermined(ff []findings.Finding) []string {
	if len(ff) == 0 {
		return nil
	}
	var out []string
	unsettled := 0
	for i := range ff {
		if ff[i].RuleID == "VULN-001" && ff[i].Metadata["applicability"] == "undetermined" {
			unsettled++
		}
	}
	if unsettled > 0 {
		out = append(out, fmt.Sprintf("Whether your code reaches the vulnerable code, for %s; until upgraded, assume it does.",
			plural(unsettled, "dependency vulnerability", "dependency vulnerabilities")))
	}
	states := map[string]int{}
	for i := range ff {
		states[ff[i].Exploitability]++
	}
	confirmed, prevented := states["CONFIRMED"], states["PREVENTED"]
	// CONFIRMED and PREVENTED need deterministic evidence (nox-core/evidence);
	// everything else is a lead, however it was found. Said either way, so a
	// list of potential issues is not read as a list of proven ones.
	switch {
	case confirmed == 0 && prevented == 0 && len(ff) == 1:
		out = append(out, "Exploitability: the finding was neither confirmed exploitable nor shown to be prevented; "+
			"it is a potential issue.")
	case confirmed == 0 && prevented == 0:
		out = append(out, fmt.Sprintf("Exploitability: none of the %s was confirmed exploitable or shown to be prevented; "+
			"they are potential issues.", plural(len(ff), "finding", "findings")))
	default:
		out = append(out, fmt.Sprintf("Exploitability: %d confirmed exploitable, %d shown to be prevented, %d not settled.",
			confirmed, prevented, len(ff)-confirmed-prevented))
	}
	return out
}

// verifications groups the plan's hypotheses by where they are grounded,
// keeping only those grounded in a finding the caller reports on (or in the AI
// inventory, which no threshold narrows).
func verifications(in Input) []Verification {
	if in.Plan == nil || len(in.Plan.Hypotheses) == 0 {
		return nil
	}
	byFP := map[string]findings.Finding{}
	for fp, i := range findings.IndexByFingerprint(in.Findings) {
		byFP[fp] = in.Findings[i]
	}
	type group struct {
		v         Verification
		scenarios map[string]bool
	}
	groups := map[string]*group{}
	var order []string
	for i := range in.Plan.Hypotheses {
		h := in.Plan.Hypotheses[i]
		w, ok := hypothesisWhere(h, byFP)
		if !ok {
			continue
		}
		g, seen := groups[w]
		if !seen {
			g = &group{v: Verification{Where: w, Objective: h.Objective}, scenarios: map[string]bool{}}
			groups[w] = g
			order = append(order, w)
		}
		g.v.Hypotheses++
		g.scenarios[h.ScenarioID] = true
	}
	sort.Strings(order)
	out := make([]Verification, 0, len(order))
	for _, w := range order {
		g := groups[w]
		for s := range g.scenarios {
			g.v.Scenarios = append(g.v.Scenarios, s)
		}
		sort.Strings(g.v.Scenarios)
		out = append(out, g.v)
	}
	return out
}

func hypothesisWhere(h attack.Hypothesis, byFP map[string]findings.Finding) (string, bool) {
	if len(h.FindingFingerprints) == 0 {
		// Grounded in the AI inventory: the agent is the subject, and the
		// plan deliberately names no route for it.
		for _, step := range h.Path {
			if step.Kind == attack.StepAgent && step.Label != "" {
				return "agent " + strconv.Quote(step.Label), true
			}
		}
		return h.EntryPoint, h.EntryPoint != ""
	}
	var places []string
	for _, fp := range h.FindingFingerprints {
		if f, ok := byFP[fp]; ok {
			places = append(places, place(f)+" ("+f.RuleID+")")
		}
	}
	if len(places) == 0 {
		return "", false
	}
	sort.Strings(places)
	return strings.Join(places, ", "), true
}

func nextSteps(in Input, r Report) []string {
	var out []string
	fp := in.FindingsPath
	if fp == "" && (len(r.Issues) > 0 || len(r.Verify) > 0) {
		out = append(out, "Re-run with --format json to write findings.json; the commands below read it.")
		fp = "findings.json"
	}
	if len(r.Issues) > 0 {
		// One plan for everything above: what nox can fix as it is, what needs a
		// look first, and what only the project's owner can supply.
		out = append(out, "See what nox can fix, what needs your review, and what it cannot: nox fix plan --input "+fp)
	}
	if len(r.Verify) > 0 {
		target := in.Target
		if target == "" {
			target = "."
		}
		cmd := "nox attack plan " + target + " --findings " + fp
		if in.InventoryPath != "" {
			cmd += " --inventory " + in.InventoryPath
		}
		out = append(out, "Plan the runtime tests (offline, sends nothing): "+cmd)
	}
	if len(r.Issues) > 0 && in.FindingsPath != "" {
		out = append(out, "Record a reviewed, accepted risk as a waiver: nox vex init --input "+in.FindingsPath)
	}
	out = append(out, "Catch new issues before they are committed: nox install-hook")
	return out
}

func severityWeight(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 4
	case findings.SeverityHigh:
		return 3
	case findings.SeverityMedium:
		return 2
	case findings.SeverityLow:
		return 1
	}
	return 0
}

func confidenceWeight(c findings.Confidence) int {
	switch c {
	case findings.ConfidenceHigh:
		return 3
	case findings.ConfidenceMedium:
		return 2
	case findings.ConfidenceLow:
		return 1
	}
	return 0
}

// rank orders issues by severity times confidence: a likely high outranks an
// unlikely critical.
func rank(s findings.Severity, c findings.Confidence) int {
	cw := confidenceWeight(c)
	if cw == 0 {
		cw = 1
	}
	return severityWeight(s) * cw
}

// severityOrUnrated names a finding whose rule states no severity, instead of
// printing an empty word.
func severityOrUnrated(s findings.Severity) string {
	if s == "" {
		return "unrated"
	}
	return string(s)
}

func confidenceOrUnknown(c findings.Confidence) string {
	if c == "" {
		return "unstated"
	}
	return string(c)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// sentence reduces s to its first sentence, without the closing period, so it
// can be embedded in a longer line.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-3])) + "..."
}
