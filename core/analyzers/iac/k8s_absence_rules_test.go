package iac

import (
	"sort"
	"testing"
)

// linesOf returns the sorted start lines of ruleID's findings.
func linesOf(t *testing.T, ruleID, path, body string) []int {
	t.Helper()
	var out []int
	for _, f := range scanIaC(t, path, body) {
		if f.RuleID == ruleID {
			out = append(out, f.Location.StartLine)
		}
	}
	sort.Ints(out)
	return out
}

func sameLines(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// emptyDirVolumes holds each shape an emptyDir takes. IAC-294's old pattern made
// both braces optional, so it matched the bare key and reported all four.
const emptyDirVolumes = `apiVersion: v1
kind: Pod
metadata: {name: scratch}
spec:
  containers:
    - name: c
      image: busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79
  volumes:
    - name: flow-with-limit
      emptyDir: {sizeLimit: 1Gi}
    - name: block-with-limit
      emptyDir:
        sizeLimit: 1Gi
    - name: flow-empty
      emptyDir: {}
    - name: block-medium-no-limit
      emptyDir:
        medium: Memory
`

func TestEmptyDirReportsOnlyTheVolumesWithoutALimit(t *testing.T) {
	got := linesOf(t, "IAC-294", "deploy/pod.yaml", emptyDirVolumes)
	if want := []int{15, 17}; !sameLines(got, want) {
		t.Errorf("IAC-294 lines = %v, want %v (flow-empty and block-medium-no-limit only)", got, want)
	}
}

// Two CronJobs in one file: the first sets timeZone, the second does not. The
// `---` boundary is what keeps the first one's timeZone from answering for the
// second.
const cronJobsWithAndWithoutTimeZone = `apiVersion: batch/v1
kind: CronJob
metadata: {name: with-tz}
spec:
  schedule: "0 3 * * *"
  timeZone: "Etc/UTC"
  jobTemplate: {spec: {template: {spec: {restartPolicy: OnFailure, containers: [{name: c, image: x}]}}}}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: no-tz}
spec:
  schedule: "0 3 * * *"
  jobTemplate: {spec: {template: {spec: {restartPolicy: OnFailure, containers: [{name: c, image: x}]}}}}
`

func TestCronJobTimezoneIsAskedOnlyWhereItIsMissing(t *testing.T) {
	if got := linesOf(t, "IAC-379", "deploy/cron.yaml", cronJobsWithAndWithoutTimeZone); !sameLines(got, []int{13}) {
		t.Errorf("IAC-379 lines = %v, want [13] (the CronJob with no timeZone)", got)
	}
}

// Setting timeZone is IAC-379's remediation. IAC-385 still notes it, but must
// not score: before, one of the two rules fired on every CronJob whichever way
// it was written.
func TestSettingTheTimezoneIsNotScoredAsARisk(t *testing.T) {
	for _, f := range scanIaC(t, "deploy/cron.yaml", cronJobsWithAndWithoutTimeZone) {
		if f.RuleID == "IAC-385" && f.Severity != "info" {
			t.Errorf("IAC-385 has severity %q on line %d, want info", f.Severity, f.Location.StartLine)
		}
	}
}

// rolloutWrapping is a RollOps RolloutConfig carrying its Deployment in a block
// scalar, reduced from nox-intelligence's .rollops/noxintel.yaml. podSeccomp is
// spliced into the pod-level securityContext.
func rolloutWrapping(podSeccomp string) string {
	return `apiVersion: rollops.dev/v1
kind: RolloutConfig
metadata:
  name: app
spec:
  workload:
    kind: kubernetes
    manifest: |
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: app
      spec:
        template:
          spec:
            securityContext:
              runAsNonRoot: true
` + podSeccomp + `            containers:
              - name: app
                image: x
                securityContext:
                  allowPrivilegeEscalation: false
`
}

// The container inherits the pod's profile whether the Deployment is a file of
// its own or a string inside a wrapper.
func TestAnEmbeddedContainerInheritsItsPodsSeccompProfile(t *testing.T) {
	body := rolloutWrapping("              seccompProfile: {type: RuntimeDefault}\n")
	if got := linesOf(t, "IAC-135", ".rollops/app.yaml", body); len(got) != 0 {
		t.Errorf("IAC-135 fired at %v on a container whose embedded pod sets seccompProfile", got)
	}
}

// Recall: the same wrapper with no profile anywhere is still reported, at the
// container's securityContext line in the outer file.
func TestAnEmbeddedWorkloadWithNoProfileIsStillReported(t *testing.T) {
	got := linesOf(t, "IAC-135", ".rollops/app.yaml", rolloutWrapping(""))
	for _, l := range got {
		if l == 21 {
			return
		}
	}
	t.Errorf("IAC-135 lines = %v, want the container securityContext on line 21", got)
}
