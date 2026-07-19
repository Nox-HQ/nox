package iac

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ruleIDs lists the rule IDs of a finding slice, for readable test failures.
func ruleIDs(fs []findings.Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.RuleID
	}
	return ids
}

// ruleFires reports whether the given rule ID appears in the analyzer's
// findings for the supplied path and content. It is the primitive the absence
// regression suite is built on: for every restored rule we assert the hardened
// config is clean (no finding) and the insecure config is flagged (finding),
// proving the block-scoped absence matcher eliminated the RE2-lookahead dead
// spot without trading it for a false positive on hardened resources.
func ruleFires(t *testing.T, path, content, ruleID string) bool {
	t.Helper()
	a := NewAnalyzer()
	results, err := a.ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("scanning %s: %v", path, err)
	}
	for _, f := range results {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// absenceCase is one restored rule with a hardened config (property present →
// must be clean) and an insecure config (property absent → must fire).
type absenceCase struct {
	id       string
	path     string
	hardened string // has the hardening property; must NOT fire
	insecure string // lacks it; must fire
}

// TestAbsenceRules_HardenedCleanInsecureFlagged is the measurement the task
// requires: for each representative rule across every affected category, prove
// recall is restored (insecure → finding) with no false positive (hardened →
// clean). Categories: CloudFormation encryption, IAM, Azure, GCP, Dockerfile,
// Kubernetes, Terraform backend/misc.
func TestAbsenceRules_HardenedCleanInsecureFlagged(t *testing.T) {
	t.Parallel()

	cases := []absenceCase{
		// ---- CloudFormation (brace-enclosing / file span, JSON) ----
		{
			id: "IAC-051", path: "stack.json",
			hardened: `{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketEncryption":{"ServerSideEncryptionConfiguration":[]}}}}}`,
			insecure: `{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b"}}}}`,
		},
		{
			id: "IAC-058", path: "policy.json",
			hardened: `{"Resources":{"P":{"Type":"AWS::IAM::Policy","Properties":{"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{}}}]}}}}}`,
			insecure: `{"Resources":{"P":{"Type":"AWS::IAM::Policy","Properties":{"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}}}}`,
		},
		{
			id: "IAC-059", path: "vpc.json",
			hardened: `{"Resources":{"V":{"Type":"AWS::EC2::VPC","Properties":{}},"F":{"Type":"AWS::EC2::FlowLog","Properties":{}}}}`,
			insecure: `{"Resources":{"V":{"Type":"AWS::EC2::VPC","Properties":{}}}}`,
		},
		{
			id: "IAC-066", path: "sns.json",
			hardened: `{"Resources":{"T":{"Type":"AWS::SNS::Topic","Properties":{"KmsMasterKeyId":"alias/aws/sns"}}}}`,
			insecure: `{"Resources":{"T":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":"t"}}}}`,
		},
		{
			id: "IAC-074", path: "cf.json",
			hardened: `{"Resources":{"D":{"Type":"AWS::CloudFront::Distribution","Properties":{"DistributionConfig":{"WebACLId":"arn:waf"}}}}}`,
			insecure: `{"Resources":{"D":{"Type":"AWS::CloudFront::Distribution","Properties":{"DistributionConfig":{}}}}}`,
		},
		{
			id: "IAC-075", path: "ddb.json",
			hardened: `{"Resources":{"T":{"Type":"AWS::DynamoDB::Table","Properties":{"SSESpecification":{"SSEEnabled":true}}}}}`,
			insecure: `{"Resources":{"T":{"Type":"AWS::DynamoDB::Table","Properties":{"TableName":"t"}}}}`,
		},
		{
			id: "IAC-080", path: "sm.json",
			hardened: `{"Resources":{"S":{"Type":"AWS::StepFunctions::StateMachine","Properties":{"LoggingConfiguration":{"Level":"ALL"}}}}}`,
			insecure: `{"Resources":{"S":{"Type":"AWS::StepFunctions::StateMachine","Properties":{"DefinitionString":"{}"}}}}`,
		},

		// ---- Azure ARM (brace-enclosing / file span, JSON) ----
		{
			id: "IAC-082", path: "azuredeploy.json",
			hardened: `{"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"sa","properties":{"encryption":{"services":{}}}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"sa","properties":{}}]}`,
		},
		{
			id: "IAC-092", path: "web.json",
			hardened: `{"resources":[{"type":"Microsoft.Web/sites","name":"w","identity":{"type":"SystemAssigned"},"properties":{}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.Web/sites","name":"w","properties":{}}]}`,
		},
		{
			id: "IAC-094", path: "aks.json",
			hardened: `{"resources":[{"type":"Microsoft.ContainerService/managedClusters","name":"k","properties":{"networkProfile":{"networkPolicy":"calico"}}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.ContainerService/managedClusters","name":"k","properties":{"networkProfile":{}}}]}`,
		},
		{
			// AbsenceRequire: only functionapp-kind sites are in scope.
			id: "IAC-096", path: "func.json",
			hardened: `{"resources":[{"type":"Microsoft.Web/sites","kind":"functionapp","identity":{"type":"SystemAssigned"},"properties":{}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.Web/sites","kind":"functionapp","properties":{}}]}`,
		},
		{
			id: "IAC-101", path: "sb.json",
			hardened: `{"resources":[{"type":"Microsoft.ServiceBus/namespaces","name":"sb","properties":{"encryption":{"keySource":"Microsoft.KeyVault"}}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.ServiceBus/namespaces","name":"sb","properties":{}}]}`,
		},
		{
			id: "IAC-104", path: "disk.json",
			hardened: `{"resources":[{"type":"Microsoft.Compute/disks","name":"d","properties":{"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}}]}`,
			insecure: `{"resources":[{"type":"Microsoft.Compute/disks","name":"d","properties":{}}]}`,
		},

		// ---- GCP (brace-block following, HCL) ----
		{
			id: "IAC-108", path: "gcs.tf",
			hardened: "resource \"google_storage_bucket\" \"b\" {\n  name                = \"x\"\n  default_kms_key_name = \"projects/p/locations/l/keyRings/r/cryptoKeys/k\"\n}\n",
			insecure: "resource \"google_storage_bucket\" \"b\" {\n  name = \"x\"\n}\n",
		},
		{
			id: "IAC-113", path: "gke.tf",
			hardened: "resource \"google_container_cluster\" \"c\" {\n  name = \"x\"\n  workload_identity_config {\n    workload_pool = \"p.svc.id.goog\"\n  }\n}\n",
			insecure: "resource \"google_container_cluster\" \"c\" {\n  name = \"x\"\n}\n",
		},
		{
			id: "IAC-119", path: "kms.tf",
			hardened: "resource \"google_kms_crypto_key\" \"k\" {\n  name            = \"x\"\n  rotation_period = \"7776000s\"\n}\n",
			insecure: "resource \"google_kms_crypto_key\" \"k\" {\n  name = \"x\"\n}\n",
		},

		// ---- Dockerfile (file / line / line-continued span) ----
		{
			id: "IAC-121", path: "Dockerfile",
			hardened: "FROM alpine:3.19\nHEALTHCHECK CMD wget -q localhost || exit 1\nUSER app\n",
			insecure: "FROM alpine:3.19\nUSER app\n",
		},
		{
			id: "IAC-122", path: "Dockerfile",
			hardened: "FROM alpine:3.19\nUSER app\n",
			insecure: "FROM alpine:3.19\nRUN echo hi\n",
		},
		{
			id: "IAC-123", path: "Dockerfile",
			hardened: "FROM alpine:3.19\nCOPY --chown=app:app src/ /app/\n",
			insecure: "FROM alpine:3.19\nCOPY src/ /app/\n",
		},
		{
			id: "IAC-125", path: "Dockerfile",
			hardened: "FROM alpine:3.19\nCMD [\"/bin/app\"]\n",
			insecure: "FROM alpine:3.19\nCMD /bin/app --serve\n",
		},
		{
			// line-continued span: the hardening flag is on a continuation line,
			// which a single-line span would miss and falsely flag.
			id: "IAC-126", path: "Dockerfile",
			hardened: "FROM debian:12\nRUN apt-get update && apt-get install -y \\\n    --no-install-recommends curl\n",
			insecure: "FROM debian:12\nRUN apt-get update && apt-get install -y curl\n",
		},
		{
			id: "IAC-127", path: "Dockerfile",
			hardened: "FROM python:3.12\nRUN pip install --no-cache-dir requests\n",
			insecure: "FROM python:3.12\nRUN pip install requests\n",
		},
		{
			id: "IAC-129", path: "Dockerfile",
			hardened: "FROM alpine:3.19\nRUN apk add --no-cache curl\n",
			insecure: "FROM alpine:3.19\nRUN apk add curl\n",
		},

		// ---- Kubernetes (file / yaml-block / yaml-doc span) ----
		{
			// PodDisruptionBudget is a separate object → whole-file absence.
			id: "IAC-132", path: "deploy.yaml",
			hardened: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: web-pdb\n",
			insecure: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		},
		{
			id: "IAC-135", path: "pod.yaml",
			hardened: "securityContext:\n  runAsNonRoot: true\n  seccompProfile:\n    type: RuntimeDefault\n",
			insecure: "securityContext:\n  runAsNonRoot: true\n",
		},
		{
			id: "IAC-137", path: "pod.yaml",
			hardened: "spec:\n  containers:\n    - name: app\n      image: nginx\n      resources:\n        limits:\n          cpu: \"1\"\n",
			insecure: "spec:\n  containers:\n    - name: app\n      image: nginx\n",
		},
		{
			id: "IAC-145", path: "pod.yaml",
			hardened: "spec:\n  containers:\n    - name: app\n      image: nginx\n      securityContext:\n        runAsNonRoot: true\n",
			insecure: "spec:\n  containers:\n    - name: app\n      image: nginx\n",
		},
		{
			id: "IAC-148", path: "svc.yaml",
			hardened: "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  selector:\n    app: web\n",
			insecure: "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  ports:\n    - port: 80\n",
		},
		{
			id: "IAC-149", path: "ing.yaml",
			hardened: "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  tls:\n    - hosts: [web]\n",
			insecure: "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  rules:\n    - host: web\n",
		},
		{
			id: "IAC-176", path: "deploy.yaml",
			hardened: "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n",
			insecure: "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers: []\n",
		},

		// ---- Terraform backend / misc (brace-block / line span, HCL) ----
		{
			id: "IAC-162", path: "backend.tf",
			hardened: "terraform {\n  backend \"s3\" {\n    bucket  = \"b\"\n    key     = \"k\"\n    encrypt = true\n  }\n}\n",
			insecure: "terraform {\n  backend \"s3\" {\n    bucket = \"b\"\n    key    = \"k\"\n  }\n}\n",
		},
		{
			id: "IAC-163", path: "backend.tf",
			hardened: "terraform {\n  backend \"s3\" {\n    bucket         = \"b\"\n    dynamodb_table = \"locks\"\n  }\n}\n",
			insecure: "terraform {\n  backend \"s3\" {\n    bucket = \"b\"\n  }\n}\n",
		},
		{
			id: "IAC-167", path: "db.tf",
			hardened: "resource \"aws_db_instance\" \"db\" {\n  engine = \"postgres\"\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n",
			insecure: "resource \"aws_db_instance\" \"db\" {\n  engine = \"postgres\"\n}\n",
		},
		{
			id: "IAC-168", path: "mod.tf",
			hardened: "module \"x\" {\n  source = \"git::https://example.com/r.git?ref=v1.0.0\"\n}\n",
			insecure: "module \"x\" {\n  source = \"git::https://example.com/r.git\"\n}\n",
		},
		{
			id: "IAC-169", path: "versions.tf",
			hardened: "terraform {\n  required_version = \">= 1.5\"\n}\n",
			insecure: "terraform {\n  backend \"local\" {}\n}\n",
		},
		{
			id: "IAC-171", path: "outputs.tf",
			hardened: "output \"db_password\" {\n  value     = var.pw\n  sensitive = true\n}\n",
			insecure: "output \"db_password\" {\n  value = var.pw\n}\n",
		},
	}

	for _, c := range cases {
		t.Run(c.id+"_hardened_clean", func(t *testing.T) {
			if ruleFires(t, c.path, c.hardened, c.id) {
				t.Errorf("%s: hardened config was flagged (false positive)", c.id)
			}
		})
		t.Run(c.id+"_insecure_flagged", func(t *testing.T) {
			if !ruleFires(t, c.path, c.insecure, c.id) {
				t.Errorf("%s: insecure config was NOT flagged (recall gap)", c.id)
			}
		})
	}
}

// TestAbsenceRule_IAC096_RequireScoping proves AbsenceRequire narrows the rule:
// a non-functionapp Web/site without an identity must NOT trigger IAC-096, even
// though it lacks the property, because the requirement (kind functionapp) is
// unmet.
func TestAbsenceRule_IAC096_RequireScoping(t *testing.T) {
	t.Parallel()
	nonFunction := `{"resources":[{"type":"Microsoft.Web/sites","kind":"app","properties":{}}]}`
	if ruleFires(t, "web.json", nonFunction, "IAC-096") {
		t.Error("IAC-096 fired on a non-functionapp site; AbsenceRequire scoping failed")
	}
}

// TestAbsenceMatcher_Deterministic scans the same content repeatedly and
// requires identical results, upholding the deterministic-output contract.
func TestAbsenceMatcher_Deterministic(t *testing.T) {
	t.Parallel()
	content := "FROM alpine:3.19\nRUN apk add curl\n"
	a := NewAnalyzer()
	first, err := a.ScanFile("Dockerfile", []byte(content))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for i := 0; i < 5; i++ {
		next, err := a.ScanFile("Dockerfile", []byte(content))
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(next) != len(first) {
			t.Fatalf("nondeterministic finding count: %d vs %d", len(next), len(first))
		}
		for j := range first {
			if next[j].RuleID != first[j].RuleID || next[j].Location.StartLine != first[j].Location.StartLine {
				t.Fatalf("nondeterministic finding at %d", j)
			}
		}
	}
}

// TestAbsenceMatcher_MultiResourceFile ensures each insecure resource in a
// multi-document file is reported independently rather than one masking another.
func TestAbsenceMatcher_MultiResourceFile(t *testing.T) {
	t.Parallel()
	// Two Services, one with a selector (clean), one without (flagged). The
	// yaml-doc span must isolate them so the hardened doc does not silence the
	// insecure one, nor vice versa.
	content := strings.Join([]string{
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: good",
		"spec:",
		"  selector:",
		"    app: good",
		"---",
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: bad",
		"spec:",
		"  ports:",
		"    - port: 80",
		"",
	}, "\n")

	a := NewAnalyzer()
	results, err := a.ScanFile("svc.yaml", []byte(content))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var count int
	for _, f := range results {
		if f.RuleID == "IAC-148" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 IAC-148 finding (the selector-less Service), got %d", count)
	}
}
