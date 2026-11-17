package iac

import (
	"bytes"
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
//
// The workload may be a string inside the file rather than a document of it:
// RollOps' RolloutConfig, an Argo CD Application or a ConfigMap carries its
// Deployment in a block scalar. The text matcher reads straight through the
// string, so the finding exists; the parse of the outer document sees only the
// wrapper, so it was never refuted. Measured on nox-intelligence's
// .rollops/noxintel.yaml: the same Deployment was clean as a file of its own and
// reported inside the wrapper.
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
	idx := newSeccompIndex(content, 0)
	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-135" {
			kept = append(kept, f)
			continue
		}
		if kind, ok := idx.inheritedAt(f.Location.StartLine); ok {
			drop(f, "the pod-level securityContext of "+kind+" sets a seccompProfile, "+
				"which every container without its own profile inherits")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// maxEmbeddingDepth bounds the descent into block scalars. A manifest inside a
// manifest inside a manifest is already past anything real.
const maxEmbeddingDepth = 3

// seccompIndex answers, for a line of one document, whether it lies in a
// workload whose pod-level securityContext sets a seccomp profile. The
// document is parsed once; embedded manifests are parsed the first time a line
// inside one is asked about.
type seccompIndex struct {
	content   []byte
	depth     int
	resources []structural.Resource
	lines     []int
	embedded  []embeddedManifest
	inner     map[int]*seccompIndex // by index into embedded
}

func newSeccompIndex(content []byte, depth int) *seccompIndex {
	idx := &seccompIndex{content: content, depth: depth}
	if docs, err := structural.Parse(content); err == nil {
		idx.resources = structural.Resources(docs)
		// Resources are ordered by declaration line; a line belongs to the last
		// resource declared at or before it.
		idx.lines = make([]int, len(idx.resources))
		for i := range idx.resources {
			idx.lines[i] = idx.resources[i].Line
		}
		// An outer document that does not parse is not descended into either:
		// unreadable is not refuted.
		if depth < maxEmbeddingDepth {
			idx.embedded = extractEmbeddedManifests(content)
		}
	}
	return idx
}

// inheritedAt returns the kind of the workload that line belongs to when that
// workload's pod sets a seccomp profile. When the resource at the line is not
// such a workload, the line may sit inside a manifest embedded in a block
// scalar, which is asked in turn with the line shifted into it.
func (x *seccompIndex) inheritedAt(line int) (string, bool) {
	if i := sort.SearchInts(x.lines, line+1) - 1; i >= 0 && inheritsPodSeccomp(x.resources[i]) {
		return x.resources[i].Type, true
	}
	for i, em := range x.embedded {
		inner := line - em.lineOffset + 1
		if inner < 1 || inner > bytes.Count(em.content, []byte("\n")) {
			continue
		}
		if x.inner == nil {
			x.inner = map[int]*seccompIndex{}
		}
		sub, ok := x.inner[i]
		if !ok {
			sub = newSeccompIndex(em.content, x.depth+1)
			x.inner[i] = sub
		}
		return sub.inheritedAt(inner)
	}
	return "", false
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
