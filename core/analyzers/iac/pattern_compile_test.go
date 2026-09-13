package iac

import (
	"regexp"
	"sort"
	"testing"
)

// knownUncompilableIaCRules is EMPTY, and the guard below is now absolute.
//
// It once held 65 IaC rules whose patterns used RE2-incompatible negative
// lookahead to express "resource present but hardening property absent". Go's
// regexp is RE2, it rejects lookahead, and RegexMatcher.compile returns the
// error while Match answers nil — so every one of them loaded, listed in
// `nox rules`, ran on every file and matched nothing.
//
// 57 were converted to the block-scoped absence matcher. The last 8 stayed,
// each with a reason recorded here: they needed per-item scoping no span
// modelled, and "leaving them dead is safer than shipping a noisy
// approximation". That reasoning was right, and it was tested against:
//
//   - IAC-155, IAC-200 needed a span the absence matcher does have once the
//     right one is chosen — "file" for a trigger and the environment that gates
//     it on another job, "brace-enclosing" for a task-level `no_log` sibling,
//     which falls back to the indentation-bounded enclosing span in YAML.
//   - IAC-179, IAC-180, IAC-182 needed a per-SERVICE answer that names the
//     service, which no span gives. They are parsed now, per service, reusing
//     the walk IAC-501 already does (compose_service.go).
//   - IAC-159, IAC-170, IAC-173 were removed. The note's reasons held up under
//     test: branch protection is not in the workflow document, a `backend "s3"`
//     block has no `versioning` argument, and a blanket tags check needs a
//     per-type taggability table — converted without one, IAC-173 fired on
//     TestNoFalsePositives_CleanTerraform's minimal, correct security group.
//
// The set must stay empty. CheckCoherence now rejects an uncompilable pattern
// outright, so this guard is the second of two.
var knownUncompilableIaCRules = map[string]bool{}

// TestNoNewUncompilableIaCRules is the structural guard for a whole class of
// silently-dead rules. Every IaC rule pattern must compile, unless it is one of
// the tracked lookahead rules above. A new rule that fails to compile — the
// exact defect that disabled these 65 — fails the build instead of shipping.
func TestNoNewUncompilableIaCRules(t *testing.T) {
	t.Parallel()

	var newlyBroken, stillBroken []string
	for _, r := range builtinIaCRules() {
		if r.Pattern == "" {
			continue
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			if knownUncompilableIaCRules[r.ID] {
				stillBroken = append(stillBroken, r.ID)
			} else {
				newlyBroken = append(newlyBroken, r.ID)
			}
		}
	}

	if len(newlyBroken) > 0 {
		sort.Strings(newlyBroken)
		t.Errorf("%d IaC rule(s) have patterns that do not compile and so never fire: %v. "+
			"Go's regexp is RE2 and rejects lookahead (?!...); the matcher swallows the compile "+
			"error silently. Give the rule a compilable pattern.", len(newlyBroken), newlyBroken)
	}

	// The tracked set must only shrink. If a rule was fixed, drop it from the
	// set so the guard tightens.
	fixed := 0
	for id := range knownUncompilableIaCRules {
		var present bool
		for _, b := range stillBroken {
			if b == id {
				present = true
			}
		}
		if !present {
			fixed++
		}
	}
	if fixed > 0 {
		t.Errorf("%d rule(s) in knownUncompilableIaCRules now compile — remove them from the set so the guard tightens", fixed)
	}
}

// TestAbsenceRulePatternsCompile guards the replacement mechanism the same way
// the regex guard protects the originals. An absence rule's detection lives in
// its Absence* regexes, not in Pattern, so a lookahead or typo there would slip
// past TestNoNewUncompilableIaCRules (which only inspects Pattern) and silently
// disable the rule — the exact failure mode this whole change exists to fix.
// Every absence anchor/property/require pattern must compile under RE2.
func TestAbsenceRulePatternsCompile(t *testing.T) {
	t.Parallel()

	validSpans := map[string]bool{
		"file": true, "line": true, "line-continued": true,
		"brace-block": true, "brace-enclosing": true,
		"yaml-block": true, "yaml-doc": true,
	}

	for _, r := range builtinIaCRules() {
		if r.MatcherType != "absence" {
			continue
		}
		if r.AbsenceAnchor == "" || r.AbsenceProperty == "" {
			t.Errorf("%s: absence rule missing anchor or property", r.ID)
		}
		if !validSpans[r.AbsenceSpan] {
			t.Errorf("%s: unknown absence span %q", r.ID, r.AbsenceSpan)
		}
		for name, pat := range map[string]string{
			"anchor":   r.AbsenceAnchor,
			"property": r.AbsenceProperty,
			"require":  r.AbsenceRequire,
		} {
			if pat == "" {
				continue
			}
			if _, err := regexp.Compile(pat); err != nil {
				t.Errorf("%s: absence %s pattern does not compile: %v", r.ID, name, err)
			}
		}
	}
}
