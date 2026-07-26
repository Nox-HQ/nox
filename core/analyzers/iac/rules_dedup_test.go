package iac

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

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
// are not yet fixed. Nearly all follow one shape: rules_expanded.go (IAC-266 to
// IAC-500) re-implements a condition rules.go (IAC-001 to IAC-185) already
// covered, because the files are concatenated by builtinIaCRules with nothing
// comparing them.
//
// Fixing one means retiring an ID and aliasing it, so existing baselines keep
// matching instead of silently un-waiving; that is a behavioural change with
// migration consequences, so it is deliberately not bundled into this test.
//
// Like knownUncompilableIaCRules, this set must only ever SHRINK. Remove a pair
// when it is fixed; the guard below then requires it to stay fixed. A NEW
// duplicate fails the build.
var knownDuplicateRulePairs = map[struct{ a, b string }]string{
	{"IAC-005", "IAC-037"}: "generic `encrypt* = false` also matches the specific `storage_encrypted = false`",
	{"IAC-007", "IAC-065"}: "privileged: true",
	{"IAC-007", "IAC-237"}: "privileged: true (three rules cover this one condition)",
	{"IAC-065", "IAC-237"}: "privileged: true",
	{"IAC-017", "IAC-312"}: "deprecated ::set-output",
	{"IAC-018", "IAC-310"}: "continue-on-error: true, reported low AND medium",
	{"IAC-026", "IAC-291"}: "hostPID: true",
	{"IAC-027", "IAC-292"}: "hostIPC: true",
	{"IAC-030", "IAC-287"}: "automountServiceAccountToken: true",
	{"IAC-036", "IAC-283"}: "publicly_accessible = true",
	{"IAC-042", "IAC-321"}: "enable_https_traffic_only = false",
	{"IAC-111", "IAC-333"}: "enable_secure_boot = false",
	{"IAC-116", "IAC-337"}: "require_ssl = false",
	{"IAC-141", "IAC-399"}: "minReplicas: 1",
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
