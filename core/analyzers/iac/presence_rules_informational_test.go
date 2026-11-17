package iac

import (
	"regexp"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// Some rules report that a control IS present: a PodDisruptionBudget, a
// ResourceQuota, a LimitRange, topology spread, anti-affinity. Their own
// remediation is "verify the values are appropriate". They were reported at
// low and medium severity, so hardening a manifest made the scan worse: adding
// the NetworkPolicies, quota, limit range, budget and anti-affinity that
// nox-intelligence#170 asked for raised its unsuppressed findings from 16 to
// 26, every new one a rule saying the requested control was there.
//
// A presence report is information, not a weakness. The rules stay; their
// severity says what they are.
var presenceMarker = regexp.MustCompile(`(?i)\((positive|informational)\)`)

// Rules whose description has no marker but which only describe a
// configuration choice the remediation asks the reader to check.
var descriptiveRules = map[string]bool{
	"IAC-387": true, // DoesNotExist operator in node affinity
	"IAC-390": true, // preferred pod anti-affinity
	"IAC-445": true, // ResourceQuota limits pod count
	"IAC-459": true, // LimitRange targets containers
}

func TestPresenceRulesAreInformational(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range builtinIaCRules() {
		if !presenceMarker.MatchString(r.Description) && !descriptiveRules[r.ID] {
			continue
		}
		seen[r.ID] = true
		if r.Severity != findings.SeverityInfo {
			t.Errorf("%s %q reports a control's presence at %s severity; want info", r.ID, r.Description, r.Severity)
		}
	}
	for id := range descriptiveRules {
		if !seen[id] {
			t.Errorf("%s is listed as descriptive but is not in the rule set", id)
		}
	}
	// The marker must keep finding the rules it was written for; a reworded
	// description would otherwise drop out of this check silently.
	for _, id := range []string{"IAC-364", "IAC-395", "IAC-416", "IAC-442", "IAC-450", "IAC-464", "IAC-477"} {
		if !seen[id] {
			t.Errorf("%s no longer carries the (positive)/(informational) marker", id)
		}
	}
}
