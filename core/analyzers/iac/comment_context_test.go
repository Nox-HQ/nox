package iac

import "testing"

func scan(t *testing.T, path, body string) []string {
	t.Helper()
	fs, err := NewAnalyzer().ScanFile(path, []byte(body))
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", path, err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// A rule keyword written in a comment is prose about configuration. The
// manifest below declares a ConfigMap and nothing else; before this filter it
// reported IAC-395, "K8s defines PodDisruptionBudget (positive)".
func TestKeywordInAYAMLCommentIsNotConfiguration(t *testing.T) {
	ids := scan(t, "notes.yaml",
		"# This comment mentions PodDisruptionBudget and nothing else.\n"+
			"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes\ndata:\n  a: b\n")
	if len(ids) != 0 {
		t.Errorf("a comment produced findings: %v", ids)
	}
}

// Commented-out configuration is not configuration. This is the Helm values
// convention — list the option, comment it out, show the default — and it was
// the single largest source of the noise: `# namespace: default` reported as a
// resource deployed to the default namespace.
func TestCommentedOutConfigurationIsNotConfiguration(t *testing.T) {
	ids := scan(t, "values.yaml", "replicaCount: 2\n# namespace: default\n# type: LoadBalancer\n")
	for _, id := range []string{"IAC-143", "IAC-232", "IAC-034"} {
		if has(ids, id) {
			t.Errorf("%s fired on a commented-out setting: %v", id, ids)
		}
	}
}

// The asymmetry that matters. A match beginning in code and running into a
// trailing comment is REAL configuration and must survive: this filter removes
// findings, and the direction it must never fail in is dropping one that is
// partly real.
func TestCodeWithATrailingCommentIsKept(t *testing.T) {
	ids := scan(t, "release.yml",
		"on: push\npermissions:\n  contents: read\n  id-token: write # cosign keyless signing (OIDC)\n")
	if !has(ids, "IAC-306") {
		t.Errorf("a real `id-token: write` with a trailing comment was dropped: %v", ids)
	}
}

// A '#' inside a quoted YAML scalar is data, not the start of a comment. A
// filter that cut each line at the first '#' would delete the rest of this
// line and with it a container running with full host capabilities.
// r12_hash_in_quoted_value.yaml pins the same shape end to end.
func TestHashInsideAQuotedScalarDoesNotStartAComment(t *testing.T) {
	ids := scan(t, "pod.yaml",
		"apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n"+
			"      securityContext: { seLinuxOptions: { level: \"s0:c1#c2\" }, privileged: true }\n")
	if !has(ids, "IAC-007") {
		t.Errorf("privileged container after an in-string '#' was dropped: %v", ids)
	}
}

// Dockerfiles use the same '#' line comments and route to the same lexer.
func TestDockerfileCommentsAreNotInstructions(t *testing.T) {
	quiet := scan(t, "Dockerfile", "# USER root is deliberately not used here\nFROM alpine:3.20\nUSER app\n")
	for _, id := range quiet {
		if id == "IAC-002" || id == "IAC-001" {
			t.Errorf("a Dockerfile comment produced %s: %v", id, quiet)
		}
	}
	// And the real instruction still reports.
	loud := scan(t, "Dockerfile", "FROM alpine:3.20\nUSER root\n")
	if len(loud) == 0 {
		t.Error("a real `USER root` produced no finding; the filter is over-reaching")
	}
}

// Terraform is deliberately untouched: lexctx has no HCL lexer, and guessing
// at comment syntax to remove findings is the direction that hides
// vulnerabilities. This test records that as a decision, so the day an HCL
// lexer lands it fails and someone extends configLang on purpose.
func TestTerraformIsNotFilteredYet(t *testing.T) {
	if got := configLang("main.tf"); got != 0 { // 0 == lexctx.LangUnknown
		t.Errorf("configLang(main.tf) = %v; if lexctx gained an HCL lexer, extend the filter "+
			"and update issue #588 rather than only changing this test", got)
	}
}

// A `kind:` under a field that points at another object names that object; it
// does not declare this one. An HPA has no pod template, no containers and no
// securityContext to be missing. Issue #590.
func TestKindUnderAReferenceFieldIsNotADeclaration(t *testing.T) {
	ids := scan(t, "hpa.yaml",
		"apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: backend\n"+
			"spec:\n  scaleTargetRef:\n    apiVersion: apps/v1\n    kind: Deployment\n    name: backend\n"+
			"  minReplicas: 3\n  maxReplicas: 40\n")
	if has(ids, "IAC-131") {
		t.Errorf("a workload rule fired on an autoscaler's scaleTargetRef: %v", ids)
	}
}

// The reason the test keys on the enclosing FIELD and not on indentation.
// A List holds real objects under `items:`, and every rule that applies to a
// Deployment applies to one declared there. A depth rule deletes all of it,
// and no repo in the rule-diff corpus contains a List, so nothing else would
// notice. r13_workloads_inside_a_list.yaml pins this end to end.
func TestWorkloadsInsideAListAreStillDeclarations(t *testing.T) {
	ids := scan(t, "list.yaml",
		"apiVersion: v1\nkind: List\nitems:\n  - apiVersion: apps/v1\n    kind: Deployment\n"+
			"    metadata:\n      name: checkout\n    spec:\n      replicas: 3\n      template:\n"+
			"        spec:\n          containers:\n            - name: api\n              image: reg/app:1\n")
	for _, want := range []string{"IAC-131", "IAC-139", "IAC-145"} {
		if !has(ids, want) {
			t.Errorf("%s did not fire on a Deployment declared inside a List: %v", want, ids)
		}
	}
}

// A reference field nobody listed keeps producing a finding. That is the safe
// direction for an allowlist to fail in, and it is worth pinning: the opposite
// choice — treat anything nested as a reference — is what this design rejected.
func TestUnlistedNestingIsNotTreatedAsAReference(t *testing.T) {
	ids := scan(t, "tpl.yaml",
		"apiVersion: v1\nkind: Template\nobjects:\n  - apiVersion: apps/v1\n    kind: Deployment\n"+
			"    metadata:\n      name: from-template\n    spec:\n      template:\n        spec:\n"+
			"          containers:\n            - name: api\n              image: reg/app:1\n")
	if !has(ids, "IAC-131") {
		t.Errorf("a Deployment under an unlisted key `objects:` was dropped; the allowlist "+
			"must fail toward reporting: %v", ids)
	}
}
