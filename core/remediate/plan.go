// Package remediate turns an assessment into a plan of changes, and a rerun of
// the checks into a report of what those changes did.
//
// It answers the question that follows every assessment -- "can you fix
// these?" -- in two halves. Plan says which fixes nox can prepare, which need a
// person's review, and which nox cannot make at all and what it would need to.
// Verify, after anything was changed, runs the checks that produced the
// findings again and reports, per change, whether the finding is gone.
//
// Nothing here applies a change. Applying runs package managers and writes
// files, so it stays in the CLI, where a human asked for it. This package only
// decides and checks, which is what lets the CLI, the MCP fix_plan tool and the
// LSP show one plan: a second planner would be a second answer to "what would
// nox do".
//
// It reuses core/assess for the issues (so plan item 3 is assessment issue 3)
// and core/fix for what can be applied.
package remediate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/assess"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
	"github.com/nox-hq/nox/core/rules"
)

// Class says what a person has to do before a change happens.
type Class string

// The three classes.
const (
	// ClassSafe changes can be applied without a decision: a published fix on
	// the same major version, a pin that leaves the version alone.
	ClassSafe Class = "safe_to_apply"
	// ClassReview changes nox can prepare but a person should look at first,
	// because they can change behaviour nox cannot see.
	ClassReview Class = "needs_review"
	// ClassInfo issues nox cannot fix on its own. The item says what is missing.
	ClassInfo Class = "needs_information"
)

// Kind says what sort of change an item is.
type Kind string

// The kinds.
const (
	KindUpgrade       Kind = "upgrade"
	KindMajorUpgrade  Kind = "major_upgrade"
	KindActionsPin    Kind = "actions_pin"
	KindContentPatch  Kind = "content_patch"
	KindManualUpgrade Kind = "manual_upgrade"
	KindNoFix         Kind = "no_fix"
	KindCode          Kind = "code"
)

// Item is one thing the assessment listed, and what can be done about it.
type Item struct {
	// N is the item's number in the assessment, so "item 3" names the same
	// issue in both.
	N     int   `json:"n"`
	Class Class `json:"class"`
	Kind  Kind  `json:"kind"`
	// Title says what the issue is and what resolves it.
	Title string `json:"title"`
	// Why says why the item has its class.
	Why string `json:"why,omitempty"`
	// Needs says exactly what is missing, for a needs_information item.
	Needs string `json:"needs,omitempty"`
	// Command is how a person applies the change by hand.
	Command  string            `json:"command,omitempty"`
	Severity findings.Severity `json:"severity"`
	// Findings is how many findings the item stands for.
	Findings     int      `json:"findings"`
	Fingerprints []string `json:"fingerprints"`
	Rules        []string `json:"rules"`
	// Upgrade is the dependency move, for the upgrade kinds.
	Upgrade *fix.UpgradeAction `json:"upgrade,omitempty"`
	// Patches are the line edits, for a content patch.
	Patches []fix.Patch `json:"patches,omitempty"`
}

// Actionable reports whether nox can prepare a change for the item.
func (it *Item) Actionable() bool { return it.Class != ClassInfo }

// Plan is everything the assessment showed, classified.
type Plan struct {
	Items        []Item `json:"items"`
	FindingCount int    `json:"finding_count"`
	Safe         int    `json:"safe_to_apply"`
	Review       int    `json:"needs_review"`
	Info         int    `json:"needs_information"`
}

// Annotation is what a plan says about one finding, for surfaces that show a
// finding on its own (an editor diagnostic) rather than the whole plan.
type Annotation struct {
	N       int    `json:"n"`
	Class   Class  `json:"class"`
	Kind    Kind   `json:"kind"`
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// AnnotationFor finds the item a finding belongs to. The text is the item's own
// reason, so an editor and the CLI cannot tell different stories.
func (p Plan) AnnotationFor(fingerprint string) (Annotation, bool) {
	for i := range p.Items {
		it := &p.Items[i]
		for _, fp := range it.Fingerprints {
			if fp != fingerprint {
				continue
			}
			text := classHeadline[it.Class]
			if it.Why != "" {
				text += " " + it.Why
			}
			if it.Needs != "" {
				text += " Needed: " + it.Needs
			}
			return Annotation{N: it.N, Class: it.Class, Kind: it.Kind, Text: text, Command: it.Command}, true
		}
	}
	return Annotation{}, false
}

var classHeadline = map[Class]string{
	ClassSafe:   "nox can apply this fix as it is.",
	ClassReview: "nox can prepare this fix, but it needs your review.",
	ClassInfo:   "nox cannot fix this automatically.",
}

// Input is what a plan is built from.
type Input struct {
	// Findings are the active findings, as the assessment received them.
	Findings []findings.Finding
	// Rules resolves rule IDs for titles and remediation text. Nil uses the
	// built-in rules.
	Rules *rules.RuleSet
	// Root is the directory finding paths are relative to. Content patches are
	// computed against the files there; with no Root none are.
	Root string
}

// BuiltinRules is the rule set of every built-in analyzer, for callers that
// hold findings but no scan result (findings.json read back from disk).
func BuiltinRules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	for _, r := range catalog.Rules() {
		rs.Add(r)
	}
	return rs
}

// Build classifies every issue the assessment would list. Deterministic: the
// same findings and the same files give the same plan.
func Build(in Input) Plan {
	if in.Rules == nil {
		in.Rules = BuiltinRules()
	}
	report := assess.Build(assess.Input{Findings: in.Findings, Rules: in.Rules})
	reader := newFileReader(in.Root)

	plan := Plan{FindingCount: report.FindingCount, Items: []Item{}}
	for i := range report.Issues {
		it := classify(&report.Issues[i], in, reader)
		it.N = i + 1
		plan.Items = append(plan.Items, it)
		switch it.Class {
		case ClassSafe:
			plan.Safe++
		case ClassReview:
			plan.Review++
		default:
			plan.Info++
		}
	}
	return plan
}

func classify(is *assess.Issue, in Input, reader *fileReader) Item {
	it := Item{
		Title:        is.Summary,
		Severity:     is.Severity,
		Findings:     is.Findings,
		Fingerprints: is.Fingerprints,
		Rules:        ruleIDs(in.Findings, is.Fingerprints),
	}
	switch is.Kind {
	case assess.KindUpgrade:
		classifyUpgrade(&it, is, in.Root)
	case assess.KindMajorUpgrade:
		classifyMajor(&it, is)
	case assess.KindNoFix:
		classifyNoFix(&it, is)
	default:
		classifyCode(&it, is, in, reader)
	}
	return it
}

func classifyUpgrade(it *Item, is *assess.Issue, root string) {
	a := is.Upgrade
	it.Class, it.Kind, it.Upgrade, it.Command = ClassSafe, KindUpgrade, a, a.Command()
	it.Why = "The fix is published and stays on the same major version (" + versionStep(a) +
		"), so it should not change how your code uses the package."
	if transitiveNPM(root, a) {
		it.Why += " It is not a package you list yourself, so nox asks npm to move it within the ranges the packages " +
			"that use it allow; if one of them pins it lower, the change is not applied and the report says so."
	}
}

// transitiveNPM reports whether an npm upgrade targets a package the project's
// package.json does not declare. False when that cannot be read: nothing is
// claimed about a manifest nox did not see.
func transitiveNPM(root string, a *fix.UpgradeAction) bool {
	if root == "" || a.Ecosystem != "npm" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.Dir(a.Manifest), "package.json"))
	if err != nil {
		return false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil {
		return false
	}
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		var deps map[string]string
		if json.Unmarshal(manifest[section], &deps) != nil {
			continue
		}
		if _, ok := deps[a.Package]; ok {
			return false
		}
	}
	return true
}

func classifyMajor(it *Item, is *assess.Issue) {
	a := is.Upgrade
	it.Class, it.Kind, it.Upgrade, it.Command = ClassReview, KindMajorUpgrade, a, a.Command()
	it.Title = strings.TrimSuffix(it.Title, assess.MajorNote)
	it.Why = "The fix is a new major version (" + versionStep(a) +
		"). A major release is allowed to break code that uses the package, so check its release notes and run your tests."
}

func versionStep(a *fix.UpgradeAction) string {
	from := a.From
	if from == "" {
		from = "installed"
	}
	return from + " -> " + a.To
}

func classifyNoFix(it *Item, is *assess.Issue) {
	if is.FixedIn != "" {
		it.Class, it.Kind = ClassInfo, KindManualUpgrade
		it.Needs = "You to upgrade it: version " + is.FixedIn + " fixes it, but nox cannot apply upgrades for this " +
			"kind of package (or this is not a move forward from the installed version). Make the upgrade with your package manager."
		return
	}
	it.Class, it.Kind = ClassInfo, KindNoFix
	it.Needs = "A fixed version, which has not been published. Until then the choice is yours: use a workaround from the " +
		"advisory, replace the package, or record the accepted risk as a reviewed waiver (nox vex init). Re-run nox scan when a fix is published."
}

func classifyCode(it *Item, is *assess.Issue, in Input, reader *fileReader) {
	switch {
	case fix.ActionsPinRules[is.RuleID]:
		it.Class, it.Kind = ClassSafe, KindActionsPin
		it.Command = "nox fix apply"
		it.Why = "Pins each GitHub Action to the commit its tag points at, on the same major version, so the " +
			"workflow runs the same code but a moved tag can no longer change it. Looking the commits up reaches GitHub; a GITHUB_TOKEN avoids its anonymous rate limit."
	case hasContentFix(is.RuleID):
		classifyPatch(it, is, in, reader)
	default:
		it.Class, it.Kind = ClassInfo, KindCode
		it.Needs = needsFor(is, in.Rules)
	}
}

func hasContentFix(rule string) bool { _, ok := fix.ContentFixes[rule]; return ok }

func classifyPatch(it *Item, is *assess.Issue, in Input, reader *fileReader) {
	byFP := map[string]*findings.Finding{}
	for i := range in.Findings {
		byFP[in.Findings[i].Fingerprint] = &in.Findings[i]
	}
	var reviews []string
	for _, fp := range is.Fingerprints {
		f := byFP[fp]
		if f == nil {
			continue
		}
		lines, ok := reader.lines(f.Location.FilePath)
		if !ok {
			continue
		}
		if p, ok := fix.PlanPatch(f, lines); ok {
			it.Patches = append(it.Patches, p)
			if p.Review != "" {
				reviews = appendUnique(reviews, p.Review)
			}
		}
	}
	sort.SliceStable(it.Patches, func(i, j int) bool {
		a, b := it.Patches[i], it.Patches[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	it.Kind = KindContentPatch
	it.Command = "nox fix apply --include-review"
	if reader.root == "" {
		// No files to read (an adapter holding findings only): the class still
		// follows from the rule, and the lines are computed when it is applied.
		if r := fix.ContentFixes[is.RuleID].Review; r != "" {
			reviews = append(reviews, r)
		}
	}
	switch {
	case len(it.Patches) == 0 && reader.root != "":
		it.Class, it.Kind, it.Command = ClassInfo, KindCode, ""
		it.Needs = "A fresh scan: the lines this fix would change are not there any more (already changed, or the " +
			"files moved since findings.json was written). Run nox scan again and plan from the new findings."
	case len(reviews) == 0:
		it.Class = ClassSafe
		it.Command = "nox fix apply"
		it.Why = "A one-line change to a single setting, with one correct value. It changes what the pipeline reports, not what is deployed."
	default:
		it.Class = ClassReview
		it.Why = "A one-line change to a single setting, but it changes how your deployed system behaves: " +
			strings.Join(reviews, "; ") + "."
	}
}

// needsFor says what a person has to supply for an issue nox has no
// deterministic fix for. It never says "unknown": every answer names the thing
// that is needed.
func needsFor(is *assess.Issue, rs *rules.RuleSet) string {
	if n, ok := needsByRule[is.RuleID]; ok {
		return n
	}
	if n, ok := needsByClass[is.VulnClass]; ok {
		return n
	}
	if rs != nil {
		if r, ok := rs.ByID(is.RuleID); ok && strings.TrimSpace(r.Remediation) != "" {
			return "A change to your code that only you can choose. Guidance for this rule: " + strings.TrimSpace(r.Remediation)
		}
	}
	return "A change to your code that only you can choose: nox has no deterministic fix for " + is.RuleID +
		". Open the flagged location and run nox explain " + is.RuleID + " for what the rule looks for."
}

// needsByRule is for rules whose missing piece is not code but a test.
var needsByRule = map[string]string{
	"AUTHZ-001": "A two-account test. Create two users, have each own one record, then request the first user's " +
		"record while signed in as the second. If it comes back, the endpoint lacks an ownership check. " +
		"A static scan cannot see who owns a record, so only that test settles it.",
}

// needsByClass says what the code's owner has to decide, per taint class.
var needsByClass = map[string]string{
	"prompt_injection": "A decision from you: what this input may do once it reaches the model. Keep it out of the " +
		"system prompt, validate its shape and length, and limit the tools the model can call on its behalf. " +
		"The right boundary depends on your feature, so nox does not guess it.",
	"sql_injection":          "A change to the query: pass the input as a bound parameter instead of building the SQL string. Which query layer you use decides the exact edit.",
	"command_injection":      "A change to the call: pass arguments as a list instead of a shell string, or drop the shell. Which command you mean to run decides the exact edit.",
	"code_injection":         "A change to the code: remove the evaluation, or restrict it to a fixed set of choices you list.",
	"xss":                    "A change to the output: escape the value for the place it is written (HTML, attribute, script). Which templating you use decides the exact edit.",
	"ssti":                   "A change to the template: pass the input as data to the template, never as template source.",
	"path_traversal":         "A change to the path handling: resolve the path and check it stays inside the directory you intend to serve.",
	"ssrf":                   "A decision from you: which hosts this server may fetch. List them and reject everything else.",
	"unsafe_deserialization": "A change to the format: use one that carries data only (JSON), or verify a signature before loading.",
	"open_redirect":          "A decision from you: which addresses a redirect may go to. List them and reject the rest.",
	"xpath_injection":        "A change to the query: pass the input as a bound variable rather than building the XPath string.",
	"ldap_injection":         "A change to the query: escape the input for LDAP filters, or use the library's parameter form.",
	"xxe":                    "A change to the parser setup: turn off external entities and DTD loading.",
	"trust_boundary":         "A decision from you: where this input is validated before it is trusted, and what it is checked against.",
}

func ruleIDs(ff []findings.Finding, fps []string) []string {
	want := map[string]bool{}
	for _, fp := range fps {
		want[fp] = true
	}
	var out []string
	for i := range ff {
		if want[ff[i].Fingerprint] {
			out = appendUnique(out, ff[i].RuleID)
		}
	}
	sort.Strings(out)
	return out
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

// fileReader reads each file once, resolving finding paths against a root.
type fileReader struct {
	root  string
	cache map[string][]string
}

func newFileReader(root string) *fileReader {
	return &fileReader{root: root, cache: map[string][]string{}}
}

func (r *fileReader) lines(path string) ([]string, bool) {
	if r.root == "" {
		return nil, false
	}
	if l, ok := r.cache[path]; ok {
		return l, l != nil
	}
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(r.root, path)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		r.cache[path] = nil
		return nil, false
	}
	l := strings.Split(string(data), "\n")
	r.cache[path] = l
	return l, true
}
