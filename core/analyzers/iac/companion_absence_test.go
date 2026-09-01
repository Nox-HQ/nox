package iac

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// manifest is the case that motivates cross-resource resolution: three
// workloads and one PodDisruptionBudget that selects exactly one of them.
//
// The text form of IAC-132 searches the whole file for "PodDisruptionBudget",
// finds it, and reports nothing — so two workloads with no availability
// guarantee at all read as protected.
const manifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: api:1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
        - name: worker
          image: worker:1
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
        - name: db
          image: db:1
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: api
`

// The headline: a budget that selects one workload protects one workload.
func TestCompanionResolutionSeesWhoIsActuallyProtected(t *testing.T) {
	got := iacFindings(t, "manifest.yaml", manifest, "IAC-132")
	if len(got) != 2 {
		for _, f := range got {
			t.Logf("  line %d", f.Location.StartLine)
		}
		t.Fatalf("IAC-132 fired %d times, want 2 (worker and db); "+
			"the text path reports 0 because the word is in the file", len(got))
	}

	// Both findings must land on the unprotected workloads, never on api.
	for _, f := range got {
		claim := f.Metadata[rules.StructuralClaimKey]
		if strings.Contains(claim, `"api"`) {
			t.Errorf("reported the protected workload: %q", claim)
		}
		if !strings.Contains(claim, "binds to a different resource") {
			t.Errorf("claim does not say the budget binds elsewhere: %q", claim)
		}
	}
}

// A workload the budget does select must be refuted, not reported. This is the
// direction that matters most: the structural path may only ever remove a
// finding it can prove wrong.
func TestCompanionResolutionRefutesTheProtectedWorkload(t *testing.T) {
	single := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: api:1
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-pdb
spec:
  selector:
    matchLabels:
      app: api
`
	if got := iacFindings(t, "manifest.yaml", single, "IAC-132"); len(got) != 0 {
		t.Errorf("IAC-132 fired on a workload its budget selects: %+v", got)
	}
}

// A flow log that references nothing monitors nothing.
//
// This was the previous hardened fixture for IAC-059, and it passed only
// because the text path counted the word "FlowLog" as the protection existing.
func TestCompanionRefusesAnUnboundFlowLog(t *testing.T) {
	tmpl := `{"Resources":{
	  "V":{"Type":"AWS::EC2::VPC","Properties":{}},
	  "F":{"Type":"AWS::EC2::FlowLog","Properties":{}}
	}}`
	got := iacFindings(t, "vpc.json", tmpl, "IAC-059")
	if len(got) != 1 {
		t.Fatalf("IAC-059 fired %d times, want 1: a flow log with no ResourceId "+
			"targets no VPC, so this VPC is unmonitored", len(got))
	}
	if claim := got[0].Metadata[rules.StructuralClaimKey]; !strings.Contains(claim, "binds to a different resource") {
		t.Errorf("claim = %q, want it to say the flow log binds elsewhere", claim)
	}
}

// A tag whose KEY contains the companion's name is not the companion. The text
// property regex for IAC-059 is `(?i)FlowLog`, which `FlowLogsEnabled: false`
// satisfies — so a VPC with logging explicitly turned OFF read as configured.
func TestCompanionIsNotSatisfiedByMatchingText(t *testing.T) {
	tmpl := `{"Resources":{"V":{"Type":"AWS::EC2::VPC","Properties":{
	  "CidrBlock":"10.0.0.0/16",
	  "Tags":[{"Key":"FlowLogsEnabled","Value":"false"}]
	}}}}`
	if got := iacFindings(t, "vpc.json", tmpl, "IAC-059"); len(got) != 1 {
		t.Errorf("IAC-059 fired %d times, want 1: a tag naming flow logs is not a flow log", len(got))
	}
}

// A quota bounds the namespace it is scoped to and no other.
func TestCompanionResolutionScopesQuotaToItsNamespace(t *testing.T) {
	elsewhere := `apiVersion: v1
kind: Namespace
metadata:
  name: team-a
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: limits
  namespace: team-b
spec:
  hard:
    cpu: "4"
`
	if got := iacFindings(t, "ns.yaml", elsewhere, "IAC-133"); len(got) != 1 {
		t.Errorf("IAC-133 fired %d times, want 1: the quota bounds team-b, not team-a", len(got))
	}

	same := strings.Replace(elsewhere, "namespace: team-b", "namespace: team-a", 1)
	if got := iacFindings(t, "ns.yaml", same, "IAC-133"); len(got) != 0 {
		t.Errorf("IAC-133 fired on a namespace its quota bounds: %+v", got)
	}
}

// An ARM child resource binds to its parent by nesting, whatever either of them
// is named — which matters because ARM names are usually expressions.
func TestCompanionResolutionFollowsARMNesting(t *testing.T) {
	nested := `{
	  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	  "resources": [{
	    "type": "Microsoft.Sql/servers",
	    "apiVersion": "2021-11-01",
	    "name": "[parameters('serverName')]",
	    "resources": [{
	      "type": "auditingSettings",
	      "apiVersion": "2021-11-01",
	      "name": "default",
	      "properties": {"state": "Enabled"}
	    }]
	  }]
	}`
	if got := iacFindings(t, "azuredeploy.json", nested, "IAC-084"); len(got) != 0 {
		t.Errorf("IAC-084 fired on a server with a nested auditingSettings child: %+v", got)
	}

	bare := `{
	  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	  "resources": [{
	    "type": "Microsoft.Sql/servers",
	    "apiVersion": "2021-11-01",
	    "name": "sqlserver1"
	  }]
	}`
	if got := iacFindings(t, "azuredeploy.json", bare, "IAC-084"); len(got) != 1 {
		t.Errorf("IAC-084 fired %d times on an unaudited server, want 1", len(got))
	}
}

// A cross-resource finding carries evidence naming what was enumerated, so a
// reader can check the claim against the file rather than take it.
func TestCompanionFindingCarriesAStaticClaim(t *testing.T) {
	a := NewAnalyzer()
	store := reasoning.New()
	a.RecordReasoningTo(store)

	got, err := a.ScanFile("manifest.yaml", []byte(manifest))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	var target *findings.Finding
	for i := range got {
		if got[i].RuleID == "IAC-132" {
			target = &got[i]
			break
		}
	}
	if target == nil {
		t.Fatal("IAC-132 did not fire")
	}

	subject := reasoning.Candidate(target.RuleID, "manifest.yaml",
		target.Location.StartLine, target.Location.StartColumn)

	var found bool
	for _, c := range store.About(subject).Claims {
		if c.Kind == evidence.KindStatic && strings.Contains(c.Statement, "PodDisruptionBudget") {
			found = true
		}
	}
	if !found {
		t.Error("no static claim naming the companion; the finding rests on the pattern alone")
	}
}

// Content the parser cannot read must keep the text path, in both directions:
// a Helm template is not valid YAML until it is rendered, and a chart with no
// budget must still be reported.
func TestCompanionUnparseableKeepsTheTextPath(t *testing.T) {
	tmpl := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  replicas: {{ .Values.replicas }}
  template:
    spec:
      containers:
        - name: app
          image: {{ .Values.image }}
`
	if got := iacFindings(t, "deployment.yaml", tmpl, "IAC-132"); len(got) != 1 {
		t.Errorf("IAC-132 fired %d times on an unrenderable template, want 1 "+
			"from the text path: a document nox cannot read is not a document with nothing in it", len(got))
	}
}
