package iac

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// assertRetiredIntoSurvivor is the check a retirement has to pass: the
// condition the retired ID reported is still detected, exactly once, by the
// rule that absorbed it — and the retired ID is still attached to that finding
// as an alias, which is what keeps a baseline entry, a VEX statement or a
// nox:ignore comment written against it matching.
//
// A retirement that merely deletes a rule passes "no duplicate" and fails here.
func assertRetiredIntoSurvivor(t *testing.T, results []findings.Finding, retired, survivor string, want findings.Severity) {
	t.Helper()

	var matches []findings.Finding
	for i := range results {
		switch results[i].RuleID {
		case retired:
			t.Errorf("%s is retired but was still emitted", retired)
		case survivor:
			matches = append(matches, results[i])
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one %s finding (the condition %s used to double-report), got %d",
			survivor, retired, len(matches))
	}
	f := matches[0]
	if f.Severity != want {
		t.Errorf("%s severity = %s, want %s", survivor, f.Severity, want)
	}
	if !f.MatchesRuleID(retired) {
		t.Errorf("%s finding does not answer to the retired ID %s (RetiredRuleIDs=%v) — "+
			"every waiver written against %s stops matching", survivor, retired, f.RetiredRuleIDs, retired)
	}
	if len(f.AliasFingerprints) == 0 {
		t.Errorf("%s finding carries no alias fingerprint for %s — baselines keyed on the "+
			"retired ID cannot match", survivor, retired)
	}
}

// Two rules that fire on the same line for the same condition report one issue
// twice. IAC-018 ("Workflow step suppresses failures with continue-on-error",
// low) and IAC-310 ("GHA step continues on error", medium) did exactly that on
// every `continue-on-error: true` in every scanned repo.
//
// The severity split is what makes it more than cosmetic: the same condition is
// simultaneously low and medium, so a gate keyed on severity gets an arbitrary
// answer, and a baseline or VEX waiver written against one ID leaves the other
// unwaived -- the finding reads as "still open" after being explicitly accepted.
//
// The duplicate arose because rules live in several files (rules.go,
// rules_expanded.go, ...) that are concatenated by builtinIaCRules with nothing
// comparing them. This test is that comparison.
//
// It is behavioural, not textual: the two patterns above differ as strings
// (`continue-on-error\s*:\s*true` vs `continue-on-error:\s*true`) while
// matching the same input, so comparing pattern text would not have caught it.
func TestIaCRules_NoTwoRulesMatchTheSameInput(t *testing.T) {
	all := builtinIaCRules()

	type probed struct {
		rule  rules.Rule
		probe string
	}
	var probes []probed
	for _, r := range all {
		if r.Pattern == "" {
			continue
		}
		if p, ok := literalProbe(r.Pattern); ok {
			probes = append(probes, probed{rule: r, probe: p})
		}
	}
	if len(probes) == 0 {
		t.Fatal("no rule yielded a literal probe; the probe generator is broken, " +
			"so this test would pass while checking nothing")
	}

	// Absence rules carry an EMPTY Pattern -- their detection lives in
	// Absence{Anchor,Property,Require} -- and regexp.Compile("") matches every
	// string, so including them made every absence rule collide with everything.
	// Uncompilable patterns are the business of TestNoNewUncompilableIaCRules,
	// which tracks them deliberately; duplicating that check here would just
	// restate its failures.
	compiled := make(map[string]*regexp.Regexp, len(all))
	for _, r := range all {
		if r.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		compiled[r.ID] = re
	}

	// ruleID -> set of ruleIDs it collides with, deduped so each pair reports once.
	type pair = struct{ a, b string }
	collisions := map[pair]string{}

	for _, p := range probes {
		for _, other := range all {
			if other.ID == p.rule.ID {
				continue
			}
			re, ok := compiled[other.ID]
			if !ok || !re.MatchString(p.probe) {
				continue
			}
			if !filePatternsOverlap(p.rule.FilePatterns, other.FilePatterns) {
				continue // cannot apply to the same file, so cannot double-report
			}
			a, b := p.rule.ID, other.ID
			if a > b {
				a, b = b, a
			}
			if allowedOverlap[pair{a, b}] {
				continue
			}
			collisions[pair{a, b}] = p.probe
		}
	}

	// Split into newly-introduced duplicates (fail) and tracked ones (must all
	// still be present, so the set can only shrink).
	stillDuplicated := map[pair]bool{}
	for k := range collisions {
		key := k
		if _, tracked := knownDuplicateRulePairs[key]; tracked {
			stillDuplicated[key] = true
			delete(collisions, k)
		}
	}
	var fixed []string
	for k := range knownDuplicateRulePairs {
		if !stillDuplicated[k] {
			fixed = append(fixed, k.a+"+"+k.b)
		}
	}
	if len(fixed) > 0 {
		sort.Strings(fixed)
		t.Errorf("%d tracked duplicate pair(s) no longer collide: %v — remove them from "+
			"knownDuplicateRulePairs so the guard tightens", len(fixed), fixed)
	}

	if len(collisions) == 0 {
		return
	}
	keys := make([]pair, 0, len(collisions))
	for k := range collisions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].a != keys[j].a {
			return keys[i].a < keys[j].a
		}
		return keys[i].b < keys[j].b
	})
	var b strings.Builder
	b.WriteString("rules double-report the same input:\n")
	for _, k := range keys {
		b.WriteString("  " + k.a + " + " + k.b + " both match " + strconv(collisions[k]) + "\n")
	}
	b.WriteString("\nRetire one ID and alias it so existing baselines keep matching, " +
		"or -- if the two are genuinely distinct concerns that merely co-locate -- " +
		"add the pair to allowedOverlap with the reason.")
	t.Error(b.String())
}

// allowedOverlap lists rule pairs that legitimately fire on the same input
// because they report genuinely different problems. Each needs a reason.
var allowedOverlap = map[struct{ a, b string }]bool{
	// A `uses:` line can be both pinned to a mutable tag and on a deprecated
	// major version. Fixing one does not fix the other.
	{"IAC-013", "IAC-157"}: true,
}

// knownDuplicateRulePairs are pairs that DO double-report the same condition and
// are not yet fixed. Nearly all followed one shape: rules_expanded.go (IAC-266 to
// IAC-500) re-implemented a condition rules.go (IAC-001 to IAC-185) already
// covered, because the files are concatenated by builtinIaCRules with nothing
// comparing them.
//
// It is EMPTY, and that is the point: the 14 pairs it tracked were retired in
// #394. Ten IDs (IAC-237, IAC-283, IAC-287, IAC-291, IAC-292, IAC-310, IAC-312,
// IAC-321, IAC-333, IAC-337) were absorbed by the older rule that already
// reported their condition, each declaring the retirement in that rule's
// `retires` list so baselines, VEX statements and nox:ignore comments written
// against the retired ID keep matching. Two pairs were not duplicates but
// generic patterns swallowing specific ones — `encrypt\w*` over
// `storage_encrypted`, `replicas` over `minReplicas` — and were fixed by
// bounding the generic pattern with `\b` instead, so both rules survive.
//
// Like knownUncompilableIaCRules, this set must only ever SHRINK. Nothing may
// be added to it: a NEW duplicate fails the build, and the fix is to retire an
// ID (with its alias) or to narrow the pattern, not to record the overlap here.
var knownDuplicateRulePairs = map[struct{ a, b string }]string{}

// partiallyRetiredIDs are IDs that survive as rules while ONE branch of what
// they used to match moved to another rule. IAC-065 is the only one: its
// `Privileged: true` branch went to IAC-007 (which reported the same condition
// at critical), while its `User: 0|root` branch — the CloudFormation ECS
// contribution nothing else makes — stayed.
//
// Such an ID is unusual enough to be listed rather than inferred: it means a
// waiver naming it also reaches the rule that absorbed the moved branch, at the
// lines where the moved pattern matches. That is deliberate — it is the same
// condition under a new ID — but it is not something to introduce by accident.
var partiallyRetiredIDs = map[string]bool{"IAC-065": true}

// TestIaCRuleRetirements_AreWellFormed checks the migration data itself. A
// retirement whose pattern does not compile, or that names a live rule by
// mistake, silently stops keeping old waivers alive — the failure mode is
// invisible in a scan and only shows up as red gates in consuming repos.
func TestIaCRuleRetirements_AreWellFormed(t *testing.T) {
	all := builtinIaCRules()

	live := make(map[string]bool, len(all))
	for _, r := range all {
		live[r.ID] = true
	}

	declaredBy := map[string]string{}
	retirements := 0
	for _, r := range all {
		for _, retired := range r.Retires {
			retirements++
			if retired.ID == "" {
				t.Errorf("%s retires a rule with no ID", r.ID)
			}
			if retired.ID == r.ID {
				t.Errorf("%s retires itself", r.ID)
			}
			if prev, dup := declaredBy[retired.ID]; dup {
				t.Errorf("%s is retired by both %s and %s; one finding would answer to it twice",
					retired.ID, prev, r.ID)
			}
			declaredBy[retired.ID] = r.ID

			if retired.Pattern == "" {
				t.Errorf("%s retires %s with no pattern, so it cannot reproduce that rule's "+
					"fingerprints and every baseline entry for %s stops matching",
					r.ID, retired.ID, retired.ID)
				continue
			}
			if _, err := regexp.Compile(retired.Pattern); err != nil {
				t.Errorf("%s retires %s with an uncompilable pattern %q: %v",
					r.ID, retired.ID, retired.Pattern, err)
			}
			if live[retired.ID] && !partiallyRetiredIDs[retired.ID] {
				t.Errorf("%s is retired by %s but is still a live rule; either it was never "+
					"retired or the alias widens %s's waivers to a rule that still fires",
					retired.ID, r.ID, retired.ID)
			}
		}
	}
	if retirements == 0 {
		t.Fatal("no rule declares a retirement; either the retirements were dropped or this " +
			"test is looking at the wrong rule set")
	}
	for id := range partiallyRetiredIDs {
		if !live[id] {
			t.Errorf("%s is listed as partially retired but no longer exists; retire it fully "+
				"and drop it from partiallyRetiredIDs", id)
		}
	}
}

// literalProbe turns a regex into a plain string that the regex matches, or
// reports false when the pattern is too dynamic to reduce confidently. A
// conservative generator is the point: a wrong probe would invent collisions.
func literalProbe(pattern string) (string, bool) {
	s := strings.TrimPrefix(pattern, "(?i)")
	// Whitespace classes become a single literal space.
	for _, ws := range []string{`\s*`, `\s+`, `\s`} {
		s = strings.ReplaceAll(s, ws, " ")
	}
	// Unescape the escapes that denote themselves.
	for _, esc := range []string{`\.`, `\-`, `\/`, `\:`, `\_`, `\@`} {
		s = strings.ReplaceAll(s, esc, strings.TrimPrefix(esc, `\`))
	}
	if s == "" || strings.ContainsAny(s, `[]()|*+?^$.{}\`) {
		return "", false // still dynamic; no reliable literal
	}
	return s, true
}

// filePatternsOverlap reports whether two rules can ever apply to one file. An
// empty list means "any file".
func filePatternsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func strconv(s string) string { return `"` + s + `"` }
