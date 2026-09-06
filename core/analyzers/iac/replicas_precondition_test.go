package iac

import "testing"

func deployWithReplicas(r string) string {
	rep := ""
	if r != "" {
		rep = "  replicas: " + r + "\n"
	}
	return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n" + rep +
		"  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:1.25\n"
}

// A PodDisruptionBudget on a single-replica workload is not a missing
// safeguard, it is a hazard: minAvailable:1 means the eviction API may never
// remove the only pod, so `kubectl drain` blocks forever and the node cannot be
// patched. maxUnavailable:1 permits exactly the disruption a budget exists to
// prevent. Either way the advice is wrong — and IAC-132 was giving it for every
// single-replica workload in a fleet.
//
// Anti-affinity has the same shape: with one replica there is nothing to
// spread, and IAC-142's own remediation says "prevents a single node failure
// from taking down all replicas".
func TestPDBAndAntiAffinityNeedMoreThanOneReplica(t *testing.T) {
	tests := []struct {
		name     string
		replicas string
		want     bool
	}{
		{"one replica — advice would be harmful", "1", false},
		{"replicas absent — Kubernetes defaults to one", "", false},
		{"zero replicas — scaled to nothing", "0", false},
		{"two replicas", "2", true},
		{"ten replicas", "10", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := deployWithReplicas(tc.replicas)
			for _, id := range []string{"IAC-132", "IAC-142"} {
				if got := ruleFires(t, "deploy.yaml", y, id); got != tc.want {
					t.Errorf("%s fired = %v, want %v for replicas=%q", id, got, tc.want, tc.replicas)
				}
			}
		})
	}
}

// The precondition must not silence the rule where it is genuinely right: a
// multi-replica workload that has neither still gets both findings, and one
// that has them gets neither.
func TestMultiReplicaHardeningStillDiscriminates(t *testing.T) {
	hardened := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  replicas: 3\n" +
		"  template:\n    spec:\n      affinity:\n        podAntiAffinity:\n          preferredDuringSchedulingIgnoredDuringExecution: []\n" +
		"      containers:\n      - name: app\n        image: nginx:1.25\n" +
		"---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: app\nspec:\n  minAvailable: 2\n  selector:\n    matchLabels:\n      app: app\n"

	if ruleFires(t, "deploy.yaml", hardened, "IAC-142") {
		t.Error("IAC-142 fired on a Deployment that has podAntiAffinity")
	}
	if ruleFires(t, "deploy.yaml", hardened, "IAC-132") {
		t.Error("IAC-132 fired on a Deployment that has a PodDisruptionBudget")
	}
}
