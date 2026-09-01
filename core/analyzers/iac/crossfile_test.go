package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// workload is a Deployment hardened against every OTHER rule, so the only thing
// under test is whether its PodDisruptionBudget was found.
const workload = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  selector:
    matchLabels: {app: api}
  template:
    metadata:
      labels: {app: api}
    spec:
      containers:
        - name: api
          image: api@sha256:aaa
          resources: {limits: {cpu: "1"}, requests: {cpu: 100m}}
          livenessProbe: {httpGet: {path: /h, port: 8080}}
          readinessProbe: {httpGet: {path: /r, port: 8080}}
          securityContext: {runAsNonRoot: true, allowPrivilegeEscalation: false}
`

const budgetFor = `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-pdb
  namespace: prod
spec:
  minAvailable: 1
  selector:
    matchLabels: {app: %s}
`

// scanTree writes files and scans them as one artifact set, the way a real scan
// sees a manifest directory.
func scanTree(t *testing.T, files map[string]string) (*findings.FindingSet, *reasoning.Store) {
	t.Helper()
	dir := t.TempDir()
	var artifacts []discovery.Artifact
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		artifacts = append(artifacts, discovery.Artifact{Path: name, AbsPath: p})
	}
	store := reasoning.New()
	a := NewAnalyzer()
	a.RecordReasoningTo(store)
	fs, err := a.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return fs, store
}

func rule132(fs *findings.FindingSet) []findings.Finding {
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-132" {
			out = append(out, f)
		}
	}
	return out
}

// The headline. A Helm chart, a kustomize base, and every manifest directory
// puts each object in its own file, so the companion is almost never in the
// same document set — which made the common case a false positive.
func TestCompanionInAnotherFileRefutesTheFinding(t *testing.T) {
	fs, _ := scanTree(t, map[string]string{
		"deployment.yaml": workload,
		"pdb.yaml":        strings.Replace(budgetFor, "%s", "api", 1),
	})
	if got := rule132(fs); len(got) != 0 {
		t.Errorf("IAC-132 fired %d time(s) on a workload whose PodDisruptionBudget "+
			"is in the next file: %+v", len(got), got)
	}
}

// The direction that matters. A budget elsewhere that selects something else
// protects nothing here, and the cross-file pass must not clear it.
func TestCompanionInAnotherFileThatDoesNotBindLeavesTheFinding(t *testing.T) {
	fs, _ := scanTree(t, map[string]string{
		"deployment.yaml": workload,
		"pdb.yaml":        strings.Replace(budgetFor, "%s", "other", 1),
	})
	got := rule132(fs)
	if len(got) != 1 {
		t.Fatalf("IAC-132 fired %d time(s), want 1: the budget selects app=other", len(got))
	}
	// And the claim must say which case this is.
	claim := got[0].Metadata[rules.StructuralClaimKey]
	if !strings.Contains(claim, "does not cover this resource") {
		t.Errorf("the claim does not distinguish an unrelated companion from an "+
			"absent one: %q", claim)
	}
}

// A namespace mismatch across files must not bind either.
func TestCrossFileRespectsNamespace(t *testing.T) {
	budget := strings.Replace(
		strings.Replace(budgetFor, "%s", "api", 1),
		"namespace: prod", "namespace: staging", 1)
	fs, _ := scanTree(t, map[string]string{
		"deployment.yaml": workload,
		"pdb.yaml":        budget,
	})
	if got := rule132(fs); len(got) != 1 {
		t.Errorf("IAC-132 fired %d time(s), want 1: the budget is in another namespace", len(got))
	}
}

// With nothing else scanned, the per-file verdict stands unchanged. This is
// what ScanFile callers (the MCP server, the LSP) keep seeing.
func TestSingleFileBehaviourIsUnchanged(t *testing.T) {
	fs, _ := scanTree(t, map[string]string{"deployment.yaml": workload})
	if got := rule132(fs); len(got) != 1 {
		t.Errorf("IAC-132 fired %d time(s) on a lone workload, want 1", len(got))
	}
}

// The cross-file pass may only ever REMOVE a finding. If it could add one, a
// finding would depend on which directory the operator pointed at.
func TestCrossFilePassNeverAddsAFinding(t *testing.T) {
	alone, _ := scanTree(t, map[string]string{"deployment.yaml": workload})
	together, _ := scanTree(t, map[string]string{
		"deployment.yaml": workload,
		"pdb.yaml":        strings.Replace(budgetFor, "%s", "api", 1),
		"unrelated.yaml":  "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {k: v}\n",
	})

	countAlone := len(alone.Findings())
	countTogether := 0
	for _, f := range together.Findings() {
		if f.Location.FilePath == "deployment.yaml" {
			countTogether++
		}
	}
	if countTogether > countAlone {
		t.Errorf("scanning more files produced MORE findings on deployment.yaml "+
			"(%d vs %d); the cross-file pass must only refute", countTogether, countAlone)
	}
}

// A suppression has to leave a reason behind, and it must name the file the
// companion was actually found in.
func TestCrossFileRefutationRecordsWhereItLooked(t *testing.T) {
	_, store := scanTree(t, map[string]string{
		"deployment.yaml": workload,
		"pdb.yaml":        strings.Replace(budgetFor, "%s", "api", 1),
	})

	var found bool
	for _, subject := range store.Subjects() {
		for _, c := range store.About(subject).Claims {
			if !c.Refutes() || c.Kind != evidence.KindStatic {
				continue
			}
			if strings.Contains(c.Statement, "pdb.yaml") &&
				strings.Contains(c.Statement, "among the manifests scanned") {
				found = true
			}
		}
	}
	if !found {
		t.Error("the cross-file refutation left no claim naming the file it found " +
			"the companion in; an operator cannot tell this from the rule never firing")
	}
}

// A Namespace's ResourceQuota is the same shape and must work the same way.
func TestCrossFileWorksForNamespaceScopedCompanions(t *testing.T) {
	fs, _ := scanTree(t, map[string]string{
		"ns.yaml":    "apiVersion: v1\nkind: Namespace\nmetadata: {name: team-a}\n",
		"quota.yaml": "apiVersion: v1\nkind: ResourceQuota\nmetadata: {name: q, namespace: team-a}\nspec: {hard: {cpu: \"4\"}}\n",
	})
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-133" {
			t.Errorf("IAC-133 fired on a namespace whose quota is in another file: %+v", f)
		}
	}
}
