package iac

import "testing"

// Four more families decide applicability by document.
//
// #636 and #637 removed the `*.yaml` catch-all from Serverless and Kustomize.
// A corrected survey of all 485 IaC rule literals found the same shape in four
// more, and in three of them it covered the whole family:
//
//	cloudformation   30 of 30 single-format rules scoped by a YAML catch-all
//	github-actions   27 of 28
//	ansible          42 of 43
//	ci-cd            11 of 11
//
// Kubernetes is deliberately NOT gated. Its rules legitimately apply to any
// document that declares Kubernetes resources — including an Ansible task that
// embeds one, where IAC-143 reporting `namespace: default` was measured as a
// true positive — so there is no document kind to gate them to.

const cfnTemplate = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Policy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            "Action": "*"
            Resource: "*"
`

// k8sConfigMapWithIAMPolicy is the measured CloudFormation leak: an AWS IAM
// policy carried as data inside a Kubernetes ConfigMap, which is an ordinary
// way to ship one. IAC-057 reported it as "CloudFormation IAM policy with
// wildcard action".
const k8sConfigMapWithIAMPolicy = `apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-iam-policy
data:
  policy.json: |
    {
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
`

const ghaWorkflowProd = `on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: make deploy
`

// kustomizeLabelTransformer is the measured GitHub Actions leak, from podinfo:
// a Kustomize LabelTransformer carrying `environment: production` as a label,
// reported as "GHA workflow targets production environment".
const kustomizeLabelTransformer = `apiVersion: builtin
kind: LabelTransformer
metadata:
  name: labels
labels:
  app.kubernetes.io/environment: production
  app.kubernetes.io/instance: webapp
fieldSpecs:
  - path: metadata/labels
    create: true
`

const gitlabPipeline = `stages:
  - test
variables:
  DEPLOY_TOKEN: hardcoded123secret
test:
  stage: test
  script:
    - make test
`

// k8sSecret is the measured CI leak. IAC-351 ("CI variable with hardcoded
// secret", CRITICAL) reported the base64 password in a Kubernetes Secret.
const k8sSecret = `apiVersion: v1
kind: Secret
metadata:
  name: quobyte-admin-secret
type: "kubernetes.io/quobyte"
data:
  password: cXVvYnl0ZQ==
  user: YWRtaW4=
`

const ansiblePlaybook = `- hosts: all
  become: true
  tasks:
    - name: fetch installer
      shell: curl http://setup.local | sh
    - name: get page
      uri:
        url: https://example.com
        validate_certs: no
`

// helmValuesWithAnsibleShapedKeys is the measured Ansible leak. Four Ansible
// rules fired on it — IAC-195, IAC-197, IAC-199 and IAC-203 — because a
// Kubernetes lifecycle hook pipes curl to a shell and the values happen to spell
// two Ansible parameter names.
const helmValuesWithAnsibleShapedKeys = `replicaCount: 2
image:
  repository: nginx
  tag: "1.25"
extraArgs:
  validate_certs: no
  no_log: false
lifecycle:
  postStart:
    exec:
      command: ["/bin/sh", "-c", "curl http://setup.local | sh"]
`

// familyOf returns the single gated family a rule belongs to, or "".
func familyOf(t *testing.T, id string) string {
	t.Helper()
	r, ok := NewAnalyzer().Rules().ByID(id)
	if !ok {
		return ""
	}
	gates, allGated := gatesFor(r)
	if !allGated || len(gates) != 1 {
		return ""
	}
	return gates[0].tag
}

// assertFamilySilent fails naming the rule that escaped its family's gate.
func assertFamilySilent(t *testing.T, family, path, body string) {
	t.Helper()
	for _, id := range scanIDs(t, path, body) {
		if familyOf(t, id) == family {
			t.Errorf("%s is a %s rule and fired on %s; the filename was treated as "+
				"evidence that the rule applies", id, family, path)
		}
	}
}

// TestEachGatedFamilyFiresOnItsOwnDocument is the recall half, and it comes
// first: a gate that excludes everything is not a fix.
func TestEachGatedFamilyFiresOnItsOwnDocument(t *testing.T) {
	for _, tc := range []struct{ name, rule, path, body string }{
		{"cloudformation", "IAC-057", "template.yaml", cfnTemplate},
		{"github-actions", "IAC-307", "release.yml", ghaWorkflowProd},
		{"ci-cd", "IAC-351", ".gitlab-ci.yml", gitlabPipeline},
		{"ansible", "IAC-197", "playbook.yml", ansiblePlaybook},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ids := scanIDs(t, tc.path, tc.body); !contains(ids, tc.rule) {
				t.Errorf("%s did not fire on a real %s document; got %v", tc.rule, tc.name, ids)
			}
		})
	}
}

// TestEachGatedFamilyIsSilentOnAForeignDocument is the measured half. Every
// fixture below produced findings from the named family before the gate.
func TestEachGatedFamilyIsSilentOnAForeignDocument(t *testing.T) {
	for _, tc := range []struct{ name, family, path, body string }{
		{"IAM policy in a ConfigMap", "cloudformation", "configmap.yaml", k8sConfigMapWithIAMPolicy},
		{"Kustomize LabelTransformer", "github-actions", "labels.yaml", kustomizeLabelTransformer},
		{"Kubernetes Secret", "ci-cd", "secret.yaml", k8sSecret},
		{"Helm values", "ansible", "values.yaml", helmValuesWithAnsibleShapedKeys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertFamilySilent(t, tc.family, tc.path, tc.body)
		})
	}
}

// TestTheRightRuleStillReportsTheHardcodedPassword. IAC-351 reported the
// Kubernetes Secret's password at CRITICAL as a "CI variable". Dropping it must
// not leave the password unreported — measured across all 8 corpus drops, and
// IAC-225 carries every one at the same line.
func TestTheRightRuleStillReportsTheHardcodedPassword(t *testing.T) {
	if ids := scanIDs(t, "secret.yaml", k8sSecret); !contains(ids, "IAC-225") {
		t.Errorf("dropping IAC-351 left the Secret's hardcoded password unreported; "+
			"IAC-225 should carry it; got %v", ids)
	}
}

// TestARuleNamingTwoGatedFormatsNeedsOnlyOneToFit. IAC-011, IAC-155 and IAC-159
// carry both `github-actions` and `ci-cd`. A GitHub Actions workflow satisfies
// either, so they must keep firing on one — under the rule this replaces
// ("exactly one format"), they were exempt from both gates instead.
func TestARuleNamingTwoGatedFormatsNeedsOnlyOneToFit(t *testing.T) {
	const prTarget = `on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make
`
	r, ok := NewAnalyzer().Rules().ByID("IAC-011")
	if !ok {
		t.Fatal("IAC-011 not found")
	}
	if gates, allGated := gatesFor(r); !allGated || len(gates) != 2 {
		t.Errorf("IAC-011 names github-actions and ci-cd; gatesFor returned %d gates "+
			"(allGated=%v)", len(gates), allGated)
	}
	if ids := scanIDs(t, "ci.yml", prTarget); !contains(ids, "IAC-011") {
		t.Errorf("IAC-011 did not fire on a workflow using pull_request_target; got %v", ids)
	}
}

// TestAFormatTheDetectorsCannotReadIsNotJudged. "I cannot read this" is not
// "this is not one". IAC-050 is a CI rule whose file patterns include *.toml and
// *.cfg, and every detector here reads YAML, JSON or a JS/TS config — so handed
// a .toml it would answer no for the wrong reason and take the family off a
// format it never examined.
func TestAFormatTheDetectorsCannotReadIsNotJudged(t *testing.T) {
	if ids := scanIDs(t, "ci.toml", "security_enabled = false\n"); !contains(ids, "IAC-050") {
		t.Errorf("IAC-050 was gated off a .toml the detectors cannot parse; got %v", ids)
	}
}

// TestKubernetesIsNotGated states the deliberate omission, so a later change
// that adds a Kubernetes gate has to argue with this first.
func TestKubernetesIsNotGated(t *testing.T) {
	for _, g := range documentKindGates {
		if g.tag == "kubernetes" {
			t.Error("Kubernetes is gated. Its rules legitimately apply to any document " +
				"declaring Kubernetes resources — an Ansible k8s_module task among them, " +
				"where IAC-143 on `namespace: default` was measured as a true positive.")
		}
	}
}
