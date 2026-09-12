package iac

import "testing"

// The Kustomize family carried the same defect as the Serverless family:
//
//	{"kustomization.yaml", "kustomization.yml", "*.yaml", "*.yml"}
//
// where the last two entries make the first two decoration. Measured
// 2026-09-12 across the rule-diff corpus, 37 of the family's 40 findings were
// on documents that are not kustomizations at all. The fixtures below are
// those documents, reduced; each was checked to reproduce against the unfixed
// build before the gate was written, because a fixture that does not fail
// first proves only that the code compiles.

// helmValues is podinfo's charts/podinfo/values.yaml, reduced. `replicaCount:
// 1` matched IAC-238's `count:\s*1\b` and was reported as "Kustomize sets
// replica count to 1 (no HA)".
//
// It also carries the top-level `resources:` that keeps the detector honest: a
// Helm values file declares one, and so does a kustomization. What separates
// them is that this one introduces a MAPPING of limits and requests where a
// kustomization's introduces a LIST of paths.
const helmValues = `replicaCount: 1
image:
  repository: ghcr.io/stefanprodan/podinfo
  tag: 6.5.0
resources:
  limits:
    cpu: 100m
  requests:
    cpu: 10m
`

// cloudFormationTemplate is the aws-cloudformation-templates shape that
// produced 21 of the 37. `Count: 1` in a ResourceSignal — the number of
// success signals CloudFormation waits for — was reported as a Kustomize
// replica count. Note `Resources` with a capital R: kustomize's field is
// lowercase, and the detector is case-sensitive for exactly this reason.
const cloudFormationTemplate = `AWSTemplateFormatVersion: "2010-09-09"
Description: CloudWatch agent
Resources:
  Instance:
    Type: AWS::EC2::Instance
    CreationPolicy:
      ResourceSignal:
        Count: 1
        Timeout: PT15M
`

// storageClass is kubernetes/examples' glusterfs-storageclass.yaml, reduced.
// `secretNamespace: "default"` — the namespace a Heketi credential lives in,
// not where anything is deployed — matched IAC-232's `namespace:\s*default`
// and was reported as "Kustomize deploys to default namespace" at HIGH
// confidence.
const storageClass = `apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: slow
provisioner: kubernetes.io/glusterfs
parameters:
  restuser: "admin"
  secretNamespace: "default"
  secretName: "heketi-secret"
`

// kustomization is podinfo's deploy/overlays/staging/kustomization.yaml.
const kustomization = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: staging
resources:
  - ../../bases/backend
  - namespace.yaml
`

// legacyKustomization declares neither apiVersion nor kind, as kustomizations
// written before either was conventional do not. It is still a kustomization,
// and the gate has to see that: a missed finding costs more than a false one.
const legacyKustomization = `resources:
  - ../base
  - deployment.yaml
`

// deploymentNamedKustomization is a Kubernetes Deployment in a file called
// kustomization.yaml.
const deploymentNamedKustomization = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
          ports:
            - containerPort: 80
`

// privilegedPod exists for IAC-007, which is tagged `kustomize` without being
// a Kustomize rule. See TestARuleNamingSeveralFormatsIsNotGatedByOne.
const privilegedPod = `apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: nginx:1.25
      securityContext:
        privileged: true
`

// isKustomizeRuleID reports whether a rule ID belongs to the Kustomize family.
func isKustomizeRuleID(t *testing.T, id string) bool {
	t.Helper()
	r, ok := NewAnalyzer().Rules().ByID(id)
	if !ok {
		return false
	}
	return scopedToOneFormat(r, kustomizeFamilyTag)
}

// assertNoKustomizeRule fails naming the rule that escaped.
func assertNoKustomizeRule(t *testing.T, path, body string) {
	t.Helper()
	for _, id := range scanIDs(t, path, body) {
		if isKustomizeRuleID(t, id) {
			t.Errorf("%s is a Kustomize rule and fired on %s; the filename was "+
				"treated as evidence that the rule applies", id, path)
		}
	}
}

// TestAKustomizeRuleFiresOnAKustomization guards the recall direction. A
// structural gate that excludes everything is not a fix.
func TestAKustomizeRuleFiresOnAKustomization(t *testing.T) {
	ids := scanIDs(t, "kustomization.yaml", kustomization)
	if !contains(ids, "IAC-242") {
		t.Errorf("IAC-242 did not fire on a real kustomization referencing "+
			"../../bases/backend; got %v", ids)
	}
}

// TestALegacyKustomizationStillCounts covers the generous branch: a document
// with no apiVersion and no kind, recognised by a `resources:` list.
func TestALegacyKustomizationStillCounts(t *testing.T) {
	ids := scanIDs(t, "kustomization.yaml", legacyKustomization)
	if !contains(ids, "IAC-242") {
		t.Errorf("IAC-242 did not fire on a kustomization that declares no apiVersion "+
			"and no kind; the gate is stricter than the format; got %v", ids)
	}
}

// TestNoKustomizeRuleFiresOnAHelmValuesFile is one of the measured cases, and
// the one that fixes the detector's shape: `resources:` alone cannot qualify a
// document, because a Helm values file has one.
func TestNoKustomizeRuleFiresOnAHelmValuesFile(t *testing.T) {
	assertNoKustomizeRule(t, "values.yaml", helmValues)
}

// TestNoKustomizeRuleFiresOnACloudFormationTemplate is the largest measured
// case: 21 of the 37.
func TestNoKustomizeRuleFiresOnACloudFormationTemplate(t *testing.T) {
	assertNoKustomizeRule(t, "amazon_linux.yaml", cloudFormationTemplate)
}

// TestNoKustomizeRuleFiresOnAKubernetesResource. A top-level `kind:` naming
// something else is decisive, and it is what keeps every manifest in a
// repository out of the family.
func TestNoKustomizeRuleFiresOnAKubernetesResource(t *testing.T) {
	assertNoKustomizeRule(t, "glusterfs-storageclass.yaml", storageClass)
}

// TestTheNameAloneDoesNotMakeItAKustomization. The gate must hold even for the
// name the family is built around, or it does not enforce the instruction it
// exists for.
func TestTheNameAloneDoesNotMakeItAKustomization(t *testing.T) {
	assertNoKustomizeRule(t, "kustomization.yaml", deploymentNamedKustomization)
}

// TestTheRightRuleStillReportsTheSmell is the difference between narrowing
// applicability and losing coverage. IAC-231 reported `image: nginx:latest` in
// the file above as "Kustomize uses latest image tag"; with the family gated
// off, the Kubernetes rule for the same condition has to report it instead.
func TestTheRightRuleStillReportsTheSmell(t *testing.T) {
	ids := scanIDs(t, "kustomization.yaml", deploymentNamedKustomization)
	if !contains(ids, "IAC-031") {
		t.Errorf("dropping the Kustomize rule left `image: nginx:latest` unreported; "+
			"IAC-031 should carry it; got %v", ids)
	}
	ids = scanIDs(t, "glusterfs-storageclass.yaml", storageClass)
	if !contains(ids, "IAC-143") {
		t.Errorf("dropping IAC-232 left `secretNamespace: \"default\"` unreported; "+
			"IAC-143 should carry it; got %v", ids)
	}
}

// TestARuleNamingSeveralFormatsIsNotGatedByOne is a regression guard for a
// defect the corpus measurement caught mid-flight.
//
// IAC-007 ("Container runs in privileged mode", CRITICAL) absorbed IAC-065
// (CloudFormation) and IAC-237 (Kustomize) and carries all three format tags
// so their waivers keep resolving. Keying the gate on the `kustomize` tag
// alone therefore switched it off wherever the document was not a
// kustomization: 9 findings lost on Kubernetes manifests in kubernetes/
// examples, on a rule with nothing to do with Kustomize beyond having
// inherited its retired ID.
func TestARuleNamingSeveralFormatsIsNotGatedByOne(t *testing.T) {
	if ids := scanIDs(t, "pod.yaml", privilegedPod); !contains(ids, "IAC-007") {
		t.Errorf("IAC-007 did not report `privileged: true` on a Kubernetes Pod; a "+
			"rule that names several document formats was gated by one of them; got %v", ids)
	}
	r, ok := NewAnalyzer().Rules().ByID("IAC-007")
	if !ok {
		t.Fatal("IAC-007 not found")
	}
	if scopedToOneFormat(r, kustomizeFamilyTag) {
		t.Error("IAC-007 is tagged kubernetes, cloudformation and kustomize; no single " +
			"format's document kind may decide whether it applies")
	}
}

// TestTheWholeFamilyIsGatedAtOnce. The point of a structural fix is that it is
// not per-rule: a Kustomize rule added tomorrow inherits it.
func TestTheWholeKustomizeFamilyIsGatedAtOnce(t *testing.T) {
	var family int
	for _, r := range NewAnalyzer().Rules().Rules() {
		if scopedToOneFormat(r, kustomizeFamilyTag) {
			family++
		}
	}
	if family < 10 {
		t.Fatalf("expected a Kustomize rule family, found %d rules scoped to it", family)
	}
	assertNoKustomizeRule(t, "docker-compose.yml",
		"version: '3'\nservices:\n  api:\n    image: ghcr.io/acme/api:latest\n    user: root\n")
}
