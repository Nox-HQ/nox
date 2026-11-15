package iac

import "testing"

// The Kubernetes family applies to every *.yml, which includes every GitHub
// Actions workflow. There a pod-spec key can only be text: an input's
// description, a step's shell string, a PR body. Nox-HQ/.github's reusable
// remediation workflow, reduced below, documents an option as
//
//	(privileged: true -> false, runAsNonRoot: false -> true, ...)
//
// and IAC-007 reported it as "Container runs in privileged mode" (CRITICAL),
// with IAC-035 and IAC-369 on the same line: 26 of the repository's 36 score
// points, for a file that runs no container at all.

// remediationWorkflow is Nox-HQ/.github's .github/workflows/nox-remediate.yml,
// reduced to the input description and the PR-body string that matched.
const remediationWorkflow = `name: Nox Remediate
on:
  workflow_call:
    inputs:
      content-fixes:
        description: >-
          Also rewrite mechanically-fixable IaC misconfigurations in place
          (privileged: true -> false, runAsNonRoot: false -> true, and 12 more
          such rules).
        type: boolean
        default: false
jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - name: Open remediation PR
        run: |
          content_note="rewrites such as privileged: true -> false"
          echo "$content_note"
`

// privilegedPodSpec is the condition the family exists for.
const privilegedPodSpec = `apiVersion: v1
kind: Pod
metadata:
  name: debug
spec:
  containers:
    - name: shell
      image: busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79
      securityContext:
        privileged: true
        runAsNonRoot: false
`

// helmValuesPrivileged is where a chart's operator actually sets the flag: a
// values file has no apiVersion and no kind, so a gate that asked "is this a
// Kubernetes resource?" would have lost it.
const helmValuesPrivileged = `replicaCount: 2
securityContext:
  privileged: true
  runAsNonRoot: false
`

var kubernetesPodRules = []string{"IAC-007", "IAC-035", "IAC-369"}

func TestNoKubernetesRuleFiresOnAGitHubWorkflow(t *testing.T) {
	ids := scanIDs(t, ".github/workflows/nox-remediate.yml", remediationWorkflow)
	for _, id := range kubernetesPodRules {
		if contains(ids, id) {
			t.Errorf("%s fired on prose in a GitHub Actions workflow; got %v", id, ids)
		}
	}
}

// TestTheWorkflowGateIsTheDocumentNotThePath: the same workflow anywhere in
// the tree is still a workflow, and a manifest under .github/ is still a
// manifest.
func TestTheWorkflowGateIsTheDocumentNotThePath(t *testing.T) {
	if ids := scanIDs(t, "ci/remediate.yml", remediationWorkflow); contains(ids, "IAC-007") {
		t.Errorf("IAC-007 fired on a workflow outside .github/workflows; got %v", ids)
	}
	if ids := scanIDs(t, ".github/debug-pod.yaml", privilegedPodSpec); !contains(ids, "IAC-007") {
		t.Errorf("IAC-007 lost a privileged pod because of where it lives; got %v", ids)
	}
}

// TestAKubernetesRuleStillFiresWhereItApplies guards recall on both shapes a
// pod spec takes.
func TestAKubernetesRuleStillFiresWhereItApplies(t *testing.T) {
	for _, c := range []struct{ path, body string }{
		{"deploy/debug-pod.yaml", privilegedPodSpec},
		{"charts/app/values.yaml", helmValuesPrivileged},
	} {
		ids := scanIDs(t, c.path, c.body)
		for _, id := range kubernetesPodRules {
			if !contains(ids, id) {
				t.Errorf("%s did not fire on %s; got %v", id, c.path, ids)
			}
		}
	}
}
