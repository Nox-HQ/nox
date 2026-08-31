package structural

import (
	"strings"
	"testing"
)

// pdb is the companion descriptor IAC-132 carries.
var pdb = Companion{Types: []string{"PodDisruptionBudget"}, Link: LinkSelector}

// quota is IAC-133's.
var quota = Companion{Types: []string{"ResourceQuota"}, Link: LinkNamespace}

// flowLog is IAC-059's.
var flowLog = Companion{
	Types: []string{"AWS::EC2::FlowLog"},
	Link:  LinkRef,
	Path:  "Properties.ResourceId",
}

// auditing is IAC-084's.
var auditing = Companion{
	Types: []string{"Microsoft.Sql/servers/auditingSettings"},
	Link:  LinkChild,
}

func TestCompanionSelectorBinding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		absent  int
		present int
		decided bool
	}{
		{
			name:    "a budget whose selector matches the pod labels binds",
			decided: true, present: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api, tier: web}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api-pdb}
spec:
  minAvailable: 1
  selector:
    matchLabels: {app: api}
`,
		},
		{
			name: "a budget selecting a different workload leaves this one unprotected",
			// The text path cannot reach this: the word PodDisruptionBudget is
			// in the file, so it reports nothing at all.
			decided: true, absent: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: worker-pdb}
spec:
  selector:
    matchLabels: {app: worker}
`,
		},
		{
			name:    "a selector requiring more labels than the pod carries does not bind",
			decided: true, absent: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: strict}
spec:
  selector:
    matchLabels: {app: api, tier: web}
`,
		},
		{
			name:    "no budget anywhere in the document set",
			decided: true, absent: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
`,
		},
		{
			name:    "an empty selector selects every pod in the namespace",
			decided: true, present: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: catch-all}
spec:
  selector:
    matchLabels: {}
`,
		},
		{
			name:    "budgets in a different stated namespace do not bind",
			decided: true, absent: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api-pdb, namespace: staging}
spec:
  selector:
    matchLabels: {app: api}
`,
		},
		{
			name: "an omitted namespace is not a mismatch",
			// The namespace of a namespace-agnostic manifest is supplied at
			// apply time. Reading omission as a mismatch would report every
			// workload in every chart.
			decided: true, present: 1,
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api-pdb}
spec:
  selector:
    matchLabels: {app: api}
`,
		},
		{
			name: "matchExpressions is undecidable, not unbound",
			// Set-based requirements are a language this package does not
			// evaluate. Reading one as "does not match" would report a workload
			// that is very likely protected.
			content: `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers: [{name: c, image: api:1}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: expr}
spec:
  selector:
    matchExpressions:
      - {key: app, operator: In, values: [api]}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := EvaluateCompanion([]byte(tt.content), []string{"Deployment", "StatefulSet"}, pdb)
			assertVerdict(t, v, tt.decided, tt.absent, tt.present)
		})
	}
}

// TestCompanionReportsEveryUnprotectedSubject is the quantity half of the fix.
//
// The text rule bounds the property search to the whole file and reports at the
// FIRST anchor, so a manifest with three unprotected workloads produces one
// finding. Resolution is per subject, so three do.
func TestCompanionReportsEveryUnprotectedSubject(t *testing.T) {
	content := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: c, image: api:1}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: worker}
spec:
  template:
    metadata: {labels: {app: worker}}
    spec: {containers: [{name: c, image: w:1}]}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db}
spec:
  template:
    metadata: {labels: {app: db}}
    spec: {containers: [{name: c, image: db:1}]}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api-pdb}
spec:
  selector:
    matchLabels: {app: api}
`
	v := EvaluateCompanion([]byte(content), []string{"Deployment", "StatefulSet"}, pdb)
	assertVerdict(t, v, true, 2, 1)

	names := []string{v.Absent[0].Name, v.Absent[1].Name}
	if names[0] != "worker" || names[1] != "db" {
		t.Errorf("unprotected workloads = %v, want [worker db]", names)
	}
	if v.Present[0].CompanionName != "api-pdb" {
		t.Errorf("bound companion = %q, want api-pdb", v.Present[0].CompanionName)
	}
}

// TestUnlinkedIsDistinguishedFromAbsent keeps the two absent cases apart. They
// are different findings to read, and only the second is one a text search
// could ever have produced.
func TestUnlinkedIsDistinguishedFromAbsent(t *testing.T) {
	workload := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: c, image: api:1}]}
`
	elsewhere := workload + `---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: other}
spec:
  selector:
    matchLabels: {app: worker}
`

	none := EvaluateCompanion([]byte(workload), []string{"Deployment"}, pdb)
	assertVerdict(t, none, true, 1, 0)
	if none.Absent[0].Unlinked {
		t.Error("a document set with no budget at all must not report one as unlinked")
	}
	if got := none.Absent[0].Statement(true); !strings.Contains(got, "declares no PodDisruptionBudget") {
		t.Errorf("statement = %q, want it to say the document set declares none", got)
	}

	other := EvaluateCompanion([]byte(elsewhere), []string{"Deployment"}, pdb)
	assertVerdict(t, other, true, 1, 0)
	if !other.Absent[0].Unlinked {
		t.Error("a budget that binds elsewhere must be reported as unlinked")
	}
	if got := other.Absent[0].Statement(true); !strings.Contains(got, "binds to a different resource") {
		t.Errorf("statement = %q, want it to say the budget binds elsewhere", got)
	}
}

func TestCompanionNamespaceBinding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		absent  int
		present int
		decided bool
	}{
		{
			name:    "a quota scoped to the namespace binds",
			decided: true, present: 1,
			content: `
apiVersion: v1
kind: Namespace
metadata: {name: team-a}
---
apiVersion: v1
kind: ResourceQuota
metadata: {name: limits, namespace: team-a}
spec: {hard: {cpu: "4"}}
`,
		},
		{
			name:    "a quota scoped to another namespace does not",
			decided: true, absent: 1,
			content: `
apiVersion: v1
kind: Namespace
metadata: {name: team-a}
---
apiVersion: v1
kind: ResourceQuota
metadata: {name: limits, namespace: team-b}
spec: {hard: {cpu: "4"}}
`,
		},
		{
			name:    "no quota in the document set",
			decided: true, absent: 1,
			content: `
apiVersion: v1
kind: Namespace
metadata: {name: team-a}
`,
		},
		{
			name: "a quota with no namespace is undecidable",
			// It is scoped when it is applied, and this file cannot say where.
			content: `
apiVersion: v1
kind: Namespace
metadata: {name: team-a}
---
apiVersion: v1
kind: ResourceQuota
metadata: {name: limits}
spec: {hard: {cpu: "4"}}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := EvaluateCompanion([]byte(tt.content), []string{"Namespace"}, quota)
			assertVerdict(t, v, tt.decided, tt.absent, tt.present)
		})
	}
}

func TestCompanionRefBinding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		absent  int
		present int
		decided bool
	}{
		{
			name:    "the YAML short form binds",
			decided: true, present: 1,
			content: `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: !Ref Vpc
      ResourceType: VPC
      TrafficType: ALL
`,
		},
		{
			name:    "the JSON long form binds",
			decided: true, present: 1,
			content: `{
  "Resources": {
    "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
    "Logs": {
      "Type": "AWS::EC2::FlowLog",
      "Properties": {"ResourceId": {"Ref": "Vpc"}, "TrafficType": "ALL"}
    }
  }
}`,
		},
		{
			name:    "Fn::Sub binds through its placeholder",
			decided: true, present: 1,
			content: `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: !Sub "${Vpc}"
      TrafficType: ALL
`,
		},
		{
			name: "a flow log for a different VPC leaves this one unmonitored",
			// Two VPCs, one flow log. The text path sees "FlowLog" and reports
			// neither; resolution reports the one nothing watches.
			decided: true, absent: 1, present: 1,
			content: `
Resources:
  Watched:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Unwatched:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.1.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: !Ref Watched
      TrafficType: ALL
`,
		},
		{
			name: "a literal id names a VPC outside the template",
			// Referring to a resource in the same template requires an
			// intrinsic, so a literal binds to nothing declared here.
			decided: true, absent: 1,
			content: `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: vpc-0a1b2c3d
      TrafficType: ALL
`,
		},
		{
			name:    "a flow log that sets no ResourceId binds to nothing",
			decided: true, absent: 1,
			content: `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties: {TrafficType: ALL}
`,
		},
		{
			name: "a reference to a parameter is undecidable",
			// The parameter may carry this VPC at deployment time.
			content: `
Parameters:
  TargetVpc: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.0.0.0/16}
  Logs:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceId: !Ref TargetVpc
      TrafficType: ALL
`,
		},
		{
			name: "a tag containing the word FlowLog is not a flow log",
			// `FlowLogsEnabled: false` satisfies the text rule's property
			// regex, so a VPC with logging explicitly OFF reads as configured.
			decided: true, absent: 1,
			content: `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      Tags: [{Key: FlowLogsEnabled, Value: "false"}]
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := EvaluateCompanion([]byte(tt.content), []string{"AWS::EC2::VPC"}, flowLog)
			assertVerdict(t, v, tt.decided, tt.absent, tt.present)
		})
	}
}

func TestCompanionChildBinding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		absent  int
		present int
		decided bool
	}{
		{
			name: "a nested child binds by its nesting",
			// No name is read, so an expression name decides nothing here.
			decided: true, present: 1,
			content: `{
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
}`,
		},
		{
			name:    "a top-level child binds through its name prefix",
			decided: true, present: 1,
			content: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {"type": "Microsoft.Sql/servers", "apiVersion": "2021-11-01", "name": "sqlserver1"},
    {
      "type": "Microsoft.Sql/servers/auditingSettings",
      "apiVersion": "2021-11-01",
      "name": "sqlserver1/default",
      "properties": {"state": "Enabled"}
    }
  ]
}`,
		},
		{
			name:    "a child of another server does not bind",
			decided: true, absent: 1,
			content: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {"type": "Microsoft.Sql/servers", "apiVersion": "2021-11-01", "name": "sqlserver1"},
    {
      "type": "Microsoft.Sql/servers/auditingSettings",
      "apiVersion": "2021-11-01",
      "name": "other/default",
      "properties": {"state": "Enabled"}
    }
  ]
}`,
		},
		{
			name:    "a server with no auditing child anywhere",
			decided: true, absent: 1,
			content: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {"type": "Microsoft.Sql/servers", "apiVersion": "2021-11-01", "name": "sqlserver1"}
  ]
}`,
		},
		{
			name: "expression names are undecidable at the top level",
			content: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {"type": "Microsoft.Sql/servers", "apiVersion": "2021-11-01", "name": "[parameters('s')]"},
    {
      "type": "Microsoft.Sql/servers/auditingSettings",
      "apiVersion": "2021-11-01",
      "name": "[concat(parameters('s'), '/default')]"
    }
  ]
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := EvaluateCompanion([]byte(tt.content), []string{"Microsoft.Sql/servers"}, auditing)
			assertVerdict(t, v, tt.decided, tt.absent, tt.present)
		})
	}
}

// TestCompanionUndecidedFallsBackToText holds the rule that makes migrating a
// rule additive: content the parser cannot read must never read as an
// all-clear, and must never read as a finding either.
func TestCompanionUndecidedFallsBackToText(t *testing.T) {
	cases := map[string]string{
		"not YAML at all":         "FROM alpine:3\nRUN echo hi\n:::{",
		"a schema not recognised": "version: '3'\nservices:\n  web:\n    image: nginx\n",
		"no descriptor":           "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a}\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			c := pdb
			if name == "no descriptor" {
				c = Companion{}
			}
			v := EvaluateCompanion([]byte(content), []string{"Deployment"}, c)
			if v.Decided {
				t.Fatal("verdict decided; unreadable content must fall back to text matching")
			}
			if v.Reason == "" {
				t.Error("an undecided verdict must say why, for the degradation channel")
			}
		})
	}
}

// TestCompanionSubjectIsNotItsOwnCompanion guards the degenerate case where a
// rule names overlapping types: without it a resource would satisfy its own
// requirement and no rule of this shape could ever fire.
func TestCompanionSubjectIsNotItsOwnCompanion(t *testing.T) {
	content := `
apiVersion: v1
kind: Namespace
metadata: {name: team-a, namespace: team-a}
`
	c := Companion{Types: []string{"Namespace"}, Link: LinkNamespace}
	v := EvaluateCompanion([]byte(content), []string{"Namespace"}, c)
	assertVerdict(t, v, true, 1, 0)
}

func assertVerdict(t *testing.T, v Verdict, decided bool, absent, present int) {
	t.Helper()
	if v.Decided != decided {
		t.Fatalf("Decided = %v, want %v (reason: %s)", v.Decided, decided, v.Reason)
	}
	if !decided {
		return
	}
	if len(v.Absent) != absent {
		t.Errorf("absent = %d, want %d: %+v", len(v.Absent), absent, v.Absent)
	}
	if len(v.Present) != present {
		t.Errorf("present = %d, want %d: %+v", len(v.Present), present, v.Present)
	}
}
