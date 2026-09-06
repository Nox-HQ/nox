package iac

import "testing"

// A CronJob with no probes, no resource constraints and no security context —
// so every rule that claims to cover batch workloads has something to find.
const cronJobNoHardening = `apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: dump
            image: postgres:16
            command: ["pg_dump"]
`

// Liveness and readiness probes are for containers that are meant to keep
// running. A Job container is meant to finish.
//
// A liveness probe restarts the container the kubelet judges unhealthy, which
// for batch work re-runs the job body from the start — worse than the hang it
// reacts to when the work is a migration or a half-written backup. Kubernetes
// answers "this Job is stuck" with activeDeadlineSeconds, not liveness.
//
// Readiness is more clearly beside the point: it gates a pod's membership in a
// Service's endpoints, and a Job's pod is behind no Service. There is no
// traffic to withhold.
//
// Both rules were firing on every CronJob in the fleet, recommending a change
// their own remediation text cannot justify.
func TestProbeRulesDoNotApplyToBatchWorkloads(t *testing.T) {
	for _, id := range []string{"IAC-139", "IAC-140"} {
		if ruleFires(t, "cronjob.yaml", cronJobNoHardening, id) {
			t.Errorf("%s fired on a CronJob; probes are for long-running containers", id)
		}
	}
}

// The narrowing must not take the rules that are right about batch work with
// it. Limits and requests govern scheduling and node pressure, and a security
// context applies to any pod — a backup Job needs all three exactly as much as
// a Deployment does.
func TestBatchWorkloadsKeepTheRulesThatDoApply(t *testing.T) {
	for _, id := range []string{"IAC-137", "IAC-138", "IAC-145"} {
		if !ruleFires(t, "cronjob.yaml", cronJobNoHardening, id) {
			t.Errorf("%s stopped firing on an unhardened CronJob", id)
		}
	}
}

// And the probe rules must still work where they belong.
func TestProbeRulesStillFireOnLongRunningWorkloads(t *testing.T) {
	deployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.25
`
	for _, id := range []string{"IAC-139", "IAC-140"} {
		if !ruleFires(t, "deploy.yaml", deployment, id) {
			t.Errorf("%s stopped firing on a Deployment with no probes", id)
		}
	}
}
