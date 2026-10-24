package iac

import (
	"sort"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules/structural"
)

// IAC-135 asks of each `securityContext:` block whether it mentions
// seccompProfile. Kubernetes answers a different question: a seccomp profile on
// the POD's securityContext applies to every container that does not set its
// own, so the container block of a pod that set
//
//	securityContext:
//	  seccompProfile: {type: RuntimeDefault}
//
// one level up is hardened, and reporting it as missing a profile is noise on
// exactly the configuration the rule asks people to write. The text matcher
// cannot see across blocks, and moving the rule to a structural verdict would
// have changed where it reports (the workload, not the securityContext line)
// and what it reports on (every workload with no securityContext at all), taking
// every baseline and waiver written against it with it. So the rule is left
// alone and this refiner drops the findings the document refutes.

// podSeccompPaths are where each workload kind keeps the pod-level profile.
var podSeccompPaths = []string{
	"spec.securityContext.seccompProfile",
	"spec.template.spec.securityContext.seccompProfile",
	"spec.jobTemplate.spec.template.spec.securityContext.seccompProfile",
}

var seccompWorkloadKinds = []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}

// dropSeccompInheritedFromPod removes IAC-135 findings that sit inside a
// workload whose pod-level securityContext sets a seccomp profile. A file that
// does not parse as Kubernetes keeps every finding: unreadable is not refuted.
func dropSeccompInheritedFromPod(in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	var any135 bool
	for i := range in {
		if in[i].RuleID == "IAC-135" {
			any135 = true
			break
		}
	}
	if !any135 {
		return in
	}
	docs, err := structural.Parse(content)
	if err != nil {
		return in
	}
	resources := structural.Resources(docs)
	if len(resources) == 0 {
		return in
	}
	// Resources are ordered by declaration line; a finding belongs to the last
	// resource declared at or before its line.
	lines := make([]int, len(resources))
	for i := range resources {
		lines[i] = resources[i].Line
	}

	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-135" {
			kept = append(kept, f)
			continue
		}
		i := sort.SearchInts(lines, f.Location.StartLine+1) - 1
		if i >= 0 && inheritsPodSeccomp(resources[i]) {
			drop(f, "the pod-level securityContext of "+resources[i].Type+" sets a seccompProfile, "+
				"which every container without its own profile inherits")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

func inheritsPodSeccomp(r structural.Resource) bool {
	if len(structural.OfTypes([]structural.Resource{r}, seccompWorkloadKinds)) == 0 {
		return false
	}
	for _, p := range podSeccompPaths {
		if structural.Has(r.Props, p) {
			return true
		}
	}
	return false
}
