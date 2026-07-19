package iac

import (
	"regexp"
	"sort"
	"testing"
)

// knownUncompilableIaCRules are IaC rules whose patterns use RE2-incompatible
// negative lookahead (?!...) to express "resource present but hardening
// property absent". Go's regexp is RE2, which rejects lookahead, and the rule
// matcher silently swallows the compile error — so these 65 rules NEVER fire.
// Whole categories are affected: most Azure coverage, Dockerfile hardening,
// Kubernetes hardening, CloudFormation encryption, and Terraform backend rules.
//
// They are listed here, not hidden, so the gap is a recorded and testable
// decision rather than an accident. The real fix is block-scoped absence
// checking (match the resource, then confirm the companion property is absent
// within that resource's span), which RE2 cannot express as a single pattern —
// it needs structured parsing or a two-pass matcher. Converting a rule out of
// this set means giving it a compilable pattern; the guard below then requires
// it to actually work.
//
// The set must only ever SHRINK. TestNoNewUncompilableIaCRules fails the build
// if a rule outside it fails to compile, so a new lookahead pattern cannot be
// added silently the way these were.
var knownUncompilableIaCRules = map[string]bool{
	"IAC-051": true, "IAC-058": true, "IAC-059": true, "IAC-066": true, "IAC-074": true,
	"IAC-075": true, "IAC-079": true, "IAC-080": true, "IAC-082": true, "IAC-084": true,
	"IAC-086": true, "IAC-092": true, "IAC-094": true, "IAC-095": true, "IAC-096": true,
	"IAC-097": true, "IAC-098": true, "IAC-099": true, "IAC-100": true, "IAC-101": true,
	"IAC-102": true, "IAC-104": true, "IAC-108": true, "IAC-113": true, "IAC-119": true,
	"IAC-121": true, "IAC-122": true, "IAC-123": true, "IAC-124": true, "IAC-125": true,
	"IAC-126": true, "IAC-127": true, "IAC-129": true, "IAC-132": true, "IAC-133": true,
	"IAC-134": true, "IAC-135": true, "IAC-137": true, "IAC-138": true, "IAC-139": true,
	"IAC-140": true, "IAC-142": true, "IAC-145": true, "IAC-146": true, "IAC-147": true,
	"IAC-148": true, "IAC-149": true, "IAC-153": true, "IAC-155": true, "IAC-159": true,
	"IAC-162": true, "IAC-163": true, "IAC-164": true, "IAC-167": true, "IAC-168": true,
	"IAC-169": true, "IAC-170": true, "IAC-171": true, "IAC-173": true, "IAC-176": true,
	"IAC-179": true, "IAC-180": true, "IAC-182": true, "IAC-183": true, "IAC-200": true,
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
