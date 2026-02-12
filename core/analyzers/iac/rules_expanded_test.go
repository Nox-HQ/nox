package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Count test
// ---------------------------------------------------------------------------

func TestExpandedRules_Count(t *testing.T) {
	rules := builtinExpandedIaCRules()
	if got := len(rules); got != 100 {
		t.Errorf("expected 100 expanded rules, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Terraform State & Backend (IAC-266 to IAC-272)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC266_TerraformLocalBackend(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
`)
	results, err := a.ScanFile("main.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-266" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-266 to be detected")
	}
}

func TestExpandedDetect_IAC267_TerraformS3Backend(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`terraform {
  backend "s3" {
    bucket = "my-state"
  }
}
`)
	results, err := a.ScanFile("main.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-267" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-267 to be detected")
	}
}

func TestExpandedDetect_IAC269_TerraformSensitiveFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`output "db_password" {
  value     = var.db_password
  sensitive = false
}
`)
	results, err := a.ScanFile("outputs.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-269" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-269 to be detected")
	}
}

func TestExpandedDetect_IAC271_TerraformHardcodedCredentials(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}
`)
	results, err := a.ScanFile("provider.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-271" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-271 to be detected")
	}
}

func TestExpandedDetect_IAC272_TerraformVariableDefault(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`variable "db_password" {
  type    = string
  default = "mysecretpassword123"
}
`)
	results, err := a.ScanFile("variables.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-272" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-272 to be detected")
	}
}

// ---------------------------------------------------------------------------
// AWS Resources (IAC-273 to IAC-285)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC273_EC2WithoutIMDSv2(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}
`)
	results, err := a.ScanFile("ec2.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-273" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-273 to be detected")
	}
}

func TestExpandedDetect_IAC280_DeletionProtectionDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  deletion_protection = false
}
`)
	results, err := a.ScanFile("rds.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-280" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-280 to be detected")
	}
}

func TestExpandedDetect_IAC281_ForceDestroyEnabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_s3_bucket" "data" {
  bucket        = "my-data-bucket"
  force_destroy = true
}
`)
	results, err := a.ScanFile("s3.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-281" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-281 to be detected")
	}
}

func TestExpandedDetect_IAC283_PubliclyAccessible(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_db_instance" "default" {
  publicly_accessible = true
}
`)
	results, err := a.ScanFile("rds.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-283" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-283 to be detected")
	}
}

func TestExpandedDetect_IAC285_MultiAZFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_db_instance" "default" {
  multi_az = false
}
`)
	results, err := a.ScanFile("rds.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-285" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-285 to be detected")
	}
}

// ---------------------------------------------------------------------------
// Kubernetes Advanced (IAC-286 to IAC-305)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC288_ClusterAdminBinding(t *testing.T) {
	a := NewAnalyzer()
	// IAC-288 pattern: (?i)roleRef:(?:.*\n){0,3}.*name:\s*['"]?cluster-admin
	// keywords: ["cluster-admin", "ClusterRoleBinding"] -- "cluster-admin" is lowercase
	content := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: admin
`)
	results, err := a.ScanFile("rbac.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-288" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-288 to be detected")
	}
}

func TestExpandedDetect_IAC289_RBACWildcardAPIGroup(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["apiGroups", "*"] -- "*" matches any content with *
	content := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-permissive
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`)
	results, err := a.ScanFile("rbac.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-289" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-289 to be detected")
	}
}

func TestExpandedDetect_IAC290_RBACWildcardVerbs(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["verbs", "*"] -- "verbs" is lowercase
	content := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-verbs
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]
`)
	results, err := a.ScanFile("rbac.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-290" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-290 to be detected")
	}
}

func TestExpandedDetect_IAC297_LoadBalancerOpenToAll(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["loadBalancerSourceRanges", "0.0.0.0"] -- "0.0.0.0" matches
	content := []byte(`apiVersion: v1
kind: Service
metadata:
  name: public-lb
spec:
  type: LoadBalancer
  loadBalancerSourceRanges:
    - 0.0.0.0/0
  ports:
  - port: 80
`)
	results, err := a.ScanFile("service.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-297" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-297 to be detected")
	}
}

func TestExpandedDetect_IAC301_UnconfinedAppArmor(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["apparmor", "unconfined"] -- both lowercase
	content := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: unconfined
spec:
  containers:
  - name: app
    image: nginx:1.25
`)
	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-301" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-301 to be detected")
	}
}

func TestExpandedDetect_IAC302_DangerousCapability(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["capabilities", "SYS_ADMIN", "ALL"] -- "capabilities" is lowercase
	content := []byte(`apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
`)
	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-302" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-302 to be detected")
	}
}

// ---------------------------------------------------------------------------
// GitHub Actions Expanded (IAC-306 to IAC-320)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC306_OIDCTokenWrite(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["id-token", "write"] -- both lowercase
	content := []byte(`name: Deploy
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
`)
	results, err := a.ScanFile(".github/workflows/deploy.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-306" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-306 to be detected")
	}
}

func TestExpandedDetect_IAC308_WorkflowDispatch(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["workflow_dispatch"] -- lowercase
	content := []byte(`name: Manual Deploy
on:
  workflow_dispatch:
    inputs:
      environment:
        description: Target environment
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
`)
	results, err := a.ScanFile(".github/workflows/deploy.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-308" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-308 to be detected")
	}
}

func TestExpandedDetect_IAC310_ContinueOnError(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["continue-on-error"] -- lowercase
	content := []byte(`name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: Run tests
      continue-on-error: true
      run: make test
`)
	results, err := a.ScanFile(".github/workflows/ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-310" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-310 to be detected")
	}
}

func TestExpandedDetect_IAC314_ContentsWrite(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["contents", "write"] -- both lowercase
	content := []byte(`name: Release
on: push
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
`)
	results, err := a.ScanFile(".github/workflows/release.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-314" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-314 to be detected")
	}
}

func TestExpandedDetect_IAC317_EventBodyInjection(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["github.event", "body"] -- both lowercase
	content := []byte(`name: Issue handler
on: issues
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
    - run: echo "${{ github.event.issue.body }}"
`)
	results, err := a.ScanFile(".github/workflows/issues.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-317" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-317 to be detected")
	}
}

func TestExpandedDetect_IAC319_SelfHostedRunner(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["self-hosted"] -- lowercase
	content := []byte(`name: Build
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
    - uses: actions/checkout@v4
`)
	results, err := a.ScanFile(".github/workflows/build.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-319" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-319 to be detected")
	}
}

// ---------------------------------------------------------------------------
// Azure (IAC-321 to IAC-330) -- these use .tf files
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC321_AzureHTTPTraffic(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "azurerm_storage_account" "main" {
  name                      = "mystorageaccount"
  enable_https_traffic_only = false
}
`)
	results, err := a.ScanFile("storage.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-321" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-321 to be detected")
	}
}

func TestExpandedDetect_IAC324_AzureAdminEnabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  admin_enabled       = true
}
`)
	results, err := a.ScanFile("acr.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-324" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-324 to be detected")
	}
}

// ---------------------------------------------------------------------------
// GCP (IAC-331 to IAC-340) -- these use .tf files
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC332_GCPIntegrityMonitoringDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "google_compute_instance" "vm" {
  name         = "test-vm"
  machine_type = "e2-medium"

  shielded_instance_config {
    enable_integrity_monitoring = false
  }
}
`)
	results, err := a.ScanFile("gcp.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-332" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-332 to be detected")
	}
}

func TestExpandedDetect_IAC337_GCPRequireSSLFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "google_sql_database_instance" "main" {
  settings {
    ip_configuration {
      require_ssl = false
    }
  }
}
`)
	results, err := a.ScanFile("sql.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-337" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-337 to be detected")
	}
}

func TestExpandedDetect_IAC338_GCPAllIPsAuthorized(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "google_sql_database_instance" "main" {
  settings {
    ip_configuration {
      authorized_networks {
        value = "0.0.0.0/0"
      }
    }
  }
}
`)
	results, err := a.ScanFile("sql.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-338" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-338 to be detected")
	}
}

// ---------------------------------------------------------------------------
// Docker Advanced (IAC-341 to IAC-345)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC342_ExposesRemoteAccessPort(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["EXPOSE", "22", "3389"] -- "22" and "3389" are digit-only, match in lowered content
	content := []byte(`FROM ubuntu:22.04
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
`)
	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-342" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-342 to be detected")
	}
}

func TestExpandedDetect_IAC344_CopyShadowFile(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["shadow"] -- lowercase
	content := []byte(`FROM alpine:3.18 AS build
RUN echo "build"

FROM alpine:3.18
COPY --from=build /etc/shadow /etc/shadow
`)
	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-344" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-344 to be detected")
	}
}

func TestExpandedDetect_IAC345_AptGetWildcard(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["apt-get", "install"] -- both lowercase
	content := []byte(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y lib*
`)
	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-345" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-345 to be detected")
	}
}

// ---------------------------------------------------------------------------
// CI/CD General (IAC-346 to IAC-355)
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC346_DockerInDocker(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["docker", "dind"] -- both lowercase
	content := []byte(`build:
  stage: build
  image: docker:dind
  script:
    - docker build -t myapp .
`)
	results, err := a.ScanFile(".gitlab-ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-346" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-346 to be detected")
	}
}

func TestExpandedDetect_IAC347_GitLabAllowFailure(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["allow_failure"] -- lowercase
	content := []byte(`security_scan:
  stage: test
  allow_failure: true
  script:
    - run-scanner
`)
	results, err := a.ScanFile(".gitlab-ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-347" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-347 to be detected")
	}
}

func TestExpandedDetect_IAC353_CurlPipedToShell(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["curl", "bash", "sh"] -- all lowercase
	content := []byte(`install:
  stage: setup
  script:
    - curl -sSL https://example.com/install.sh | bash
`)
	results, err := a.ScanFile(".gitlab-ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-353" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-353 to be detected")
	}
}

func TestExpandedDetect_IAC355_CIServiceLatestTag(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["services", "latest"] -- both lowercase
	content := []byte(`test:
  stage: test
  services:
    - postgres:latest
  script:
    - go test ./...
`)
	results, err := a.ScanFile(".gitlab-ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-355" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-355 to be detected")
	}
}

// ---------------------------------------------------------------------------
// Misc IaC (IAC-356 to IAC-365) -- K8s YAML rules
// ---------------------------------------------------------------------------

func TestExpandedDetect_IAC356_K8sPlainSecret(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["kind", "Secret"] -- "kind" is lowercase
	content := []byte(`apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  password: cGFzc3dvcmQ=
`)
	results, err := a.ScanFile("secret.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-356" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-356 to be detected")
	}
}

func TestExpandedDetect_IAC359_CronJobEveryMinute(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["schedule", "CronJob"] -- "schedule" is lowercase
	content := []byte(`apiVersion: batch/v1
kind: CronJob
metadata:
  name: frequent-job
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: busybox:1.36
`)
	results, err := a.ScanFile("cronjob.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-359" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-359 to be detected")
	}
}

func TestExpandedDetect_IAC363_RecreateStrategy(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["strategy", "Recreate"] -- "strategy" is lowercase
	content := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: app
        image: myapp:v1
`)
	results, err := a.ScanFile("deployment.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-363" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-363 to be detected")
	}
}

func TestExpandedDetect_IAC365_SystemPriorityClass(t *testing.T) {
	a := NewAnalyzer()
	// keywords: ["priorityClassName", "system"] -- "system" is lowercase
	content := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  priorityClassName: system-node-critical
  containers:
  - name: app
    image: myapp:v1
`)
	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range results {
		if f.RuleID == "IAC-365" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-365 to be detected")
	}
}

// ---------------------------------------------------------------------------
// File pattern filtering: expanded rules should not fire on wrong file types
// ---------------------------------------------------------------------------

func TestExpandedNoDetect_TerraformRuleOnYAML(t *testing.T) {
	a := NewAnalyzer()
	// Content matching IAC-271 pattern but in a YAML file
	content := []byte(`access_key = "AKIAIOSFODNN7EXAMPLE"`)
	results, err := a.ScanFile("config.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range results {
		if f.RuleID == "IAC-271" {
			t.Error("IAC-271 (Terraform hardcoded credentials) should not fire on .yaml files")
		}
	}
}

func TestExpandedNoDetect_DockerRuleOnTerraform(t *testing.T) {
	a := NewAnalyzer()
	// Content matching IAC-342 pattern but in a .tf file
	content := []byte("EXPOSE 22\n")
	results, err := a.ScanFile("main.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range results {
		if f.RuleID == "IAC-342" {
			t.Error("IAC-342 (Dockerfile EXPOSE remote port) should not fire on .tf files")
		}
	}
}
