package iac

import (
	"regexp"
	"sort"
	"testing"
)

// knownUncompilableIaCRules are IaC rules whose patterns use RE2-incompatible
// negative lookahead (?!...) to express "resource present but hardening
// property absent". Go's regexp is RE2, which rejects lookahead, and the rule
// matcher silently swallows the compile error — so these rules NEVER fired.
//
// 57 of the original 65 have since been restored: they were rewritten to use
// the block-scoped absence matcher (rules.Rule.Absence* + matcher_type
// "absence"), which locates the resource anchor, bounds its real structural
// span (brace block, YAML block/document, or whole file), and fires only when
// the hardening property is genuinely absent from that span. That is what RE2
// lookahead could not express and what a line-windowed exclusion cannot do
// safely (it flags hardened resources whose property sits outside the window).
//
// The 8 below remain: each needs per-item scoping that none of the current
// spans model precisely, so leaving them dead is safer than shipping a noisy
// approximation. They keep their (uncompilable) lookahead pattern and stay
// tracked here so the gap is recorded and testable rather than accidental:
//
//   - IAC-155 workflow_dispatch without environment — "environment" is a
//     per-job key; a file-level or brace span cannot bind it to the trigger.
//   - IAC-159 branch protection without required checks — spans a settings
//     document structure the anchor cannot delimit.
//   - IAC-170 S3 backend without versioning — an S3 backend block has no
//     `versioning` argument (that lives on the bucket resource); the rule is
//     semantically ill-posed and would only ever false-positive.
//   - IAC-173 aws_* resource without tags — many AWS resource types cannot be
//     tagged, so a blanket per-resource tags check needs a type allowlist.
//   - IAC-179 compose service without resource limits — needs the per-service
//     mapping span; the deploy/mem_limit/cpus alternatives sit at mixed depths.
//   - IAC-180 compose volume without read-only — needs per-mount parsing of the
//     `host:container[:mode]` string, not a line/block absence.
//   - IAC-182 compose service without healthcheck — needs the per-service span,
//     as IAC-179.
//   - IAC-200 Ansible sensitive var without no_log — no_log is a task-level
//     sibling key; correctly scoping it needs per-task (list-item) spans.
//
// Converting a rule out of this set means giving it a working detection; the
// guard below then requires it to actually compile/fire. The set must only ever
// SHRINK. TestNoNewUncompilableIaCRules fails the build if a rule outside it
// fails to compile, so a new lookahead pattern cannot be added silently.
var knownUncompilableIaCRules = map[string]bool{
	"IAC-155": true, "IAC-159": true, "IAC-170": true, "IAC-173": true,
	"IAC-179": true, "IAC-180": true, "IAC-182": true, "IAC-200": true,
}

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
