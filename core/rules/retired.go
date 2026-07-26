package rules

import (
	"regexp"
	"sync"

	"github.com/nox-hq/nox/core/findings"
)

// RetiredRule is an ID that a surviving rule absorbed, together with the
// pattern the retired rule used to carry.
//
// Two rules that fire on one condition report it twice, so one of the IDs has
// to go. Deleting it outright is not safe: baselines key on a fingerprint that
// hashes the rule ID, and VEX statements and nox:ignore comments name the rule
// ID directly, so every waiver written against the deleted ID would stop
// matching. The finding would come back as new under the surviving ID —
// un-waiving, in every consuming repo, something an operator explicitly
// accepted.
//
// Declaring the retirement here instead keeps those waivers working. The
// pattern is what makes it exact: the retired rule's fingerprint hashed the
// text ITS pattern matched, which is not always the text the survivor matches
// (IAC-312's `set-output name=` against IAC-017's `::set-output name=`, for
// one). Re-running the retired pattern over the matched line reproduces the
// retired rule's own match text, and therefore its exact fingerprint.
//
// It also bounds the alias: a retired ID is attached to a finding only where
// its pattern really matches, so an ID-level waiver keeps covering exactly the
// conditions that ID used to report and no more.
type RetiredRule struct {
	// ID is the retired rule's identifier, e.g. "IAC-310".
	ID string `yaml:"id"`
	// Pattern is the regex the retired rule carried at retirement. It is
	// frozen: editing it after the fact invalidates the fingerprints it
	// reproduces, which is the whole point of keeping it.
	Pattern string `yaml:"pattern"`
}

// retiredPatterns caches compiled retirement patterns. Compilation happens once
// per pattern per process rather than once per match.
var retiredPatterns sync.Map // string -> *regexp.Regexp (nil for uncompilable)

func compiledRetiredPattern(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if v, ok := retiredPatterns.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// An uncompilable retirement pattern yields no alias rather than a
		// panic: the survivor still reports the finding, and the loss is
		// limited to legacy waivers for that one ID. TestRetiredRulePatterns
		// keeps this from happening silently.
		re = nil
	}
	retiredPatterns.Store(pattern, re)
	return re
}

// retiredIdentities returns the retired rule IDs that also matched on line, and
// the fingerprints those rules would have produced at loc. Both slices are
// index-aligned and nil when the rule retires nothing.
func retiredIdentities(rule *Rule, line string, loc findings.Location) (ids, fingerprints []string) {
	for i := range rule.Retires {
		retired := rule.Retires[i]
		if retired.ID == "" {
			continue
		}
		re := compiledRetiredPattern(retired.Pattern)
		if re == nil {
			continue
		}
		matchText := re.FindString(line)
		if matchText == "" {
			// The retired rule would not have fired here, so nothing it
			// waived applies to this finding.
			continue
		}
		ids = append(ids, retired.ID)
		fingerprints = append(fingerprints, findings.ComputeFingerprint(retired.ID, loc, matchText))
	}
	return ids, fingerprints
}
