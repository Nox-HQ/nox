package iac

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// IAC-001: Dockerfile runs as root
// ---------------------------------------------------------------------------

func TestDetect_DockerfileRunsAsRoot(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nRUN apt-get update\nUSER root\nCMD [\"/app\"]\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.RuleID != "IAC-001" {
		t.Fatalf("expected RuleID IAC-001, got %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
	if f.Location.StartLine != 3 {
		t.Fatalf("expected line 3, got %d", f.Location.StartLine)
	}
}

func TestNoDetect_DockerfileNonRootUser(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nRUN apt-get update\nUSER appuser\nCMD [\"/app\"]\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range results {
		if f.RuleID == "IAC-001" {
			t.Fatal("should not flag non-root USER directive")
		}
	}
}

// ---------------------------------------------------------------------------
// IAC-002: Unpinned base image
// ---------------------------------------------------------------------------

func TestDetect_DockerfileUnpinnedBaseImage(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"no tag", "FROM ubuntu\nRUN echo hello\n"},
		{"latest tag", "FROM ubuntu:latest\nRUN echo hello\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("Dockerfile", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			found := false
			for _, f := range results {
				if f.RuleID == "IAC-002" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected IAC-002 finding for %q", tt.name)
			}
		})
	}
}

func TestNoDetect_DockerfilePinnedBaseImage(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nRUN echo hello\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range results {
		if f.RuleID == "IAC-002" {
			t.Fatal("should not flag pinned base image")
		}
	}
}

// ---------------------------------------------------------------------------
// IAC-003: Dockerfile uses ADD instead of COPY
// ---------------------------------------------------------------------------

func TestDetect_DockerfileUsesADD(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nADD . /app\nRUN echo hello\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-003" {
			found = true
			if f.Severity != findings.SeverityLow {
				t.Fatalf("expected severity low, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-003 finding for ADD instruction")
	}
}

// ---------------------------------------------------------------------------
// IAC-004: Terraform public access (0.0.0.0/0)
// ---------------------------------------------------------------------------

func TestDetect_TerraformPublicAccess(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }
}
`)

	results, err := a.ScanFile("main.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-004" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Fatalf("expected severity high, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-004 finding for 0.0.0.0/0 CIDR")
	}
}

// ---------------------------------------------------------------------------
// IAC-005: Terraform encryption disabled
// ---------------------------------------------------------------------------

func TestDetect_TerraformEncryptionDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"

  server_side_encryption_configuration {
    encrypted = false
  }
}
`)

	results, err := a.ScanFile("storage.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-005" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-005 finding for encryption disabled")
	}
}

// ---------------------------------------------------------------------------
// IAC-006: Terraform unrestricted SSH
// ---------------------------------------------------------------------------

func TestDetect_TerraformUnrestrictedSSH(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
}
`)

	results, err := a.ScanFile("security.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-006" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Fatalf("expected severity critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-006 finding for SSH port 22")
	}
}

// ---------------------------------------------------------------------------
// IAC-007: Kubernetes privileged container
// ---------------------------------------------------------------------------

func TestDetect_KubernetesPrivilegedContainer(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx:1.25
    securityContext:
      privileged: true
`)

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-007" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Fatalf("expected severity critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-007 finding for privileged container")
	}
}

// ---------------------------------------------------------------------------
// IAC-008: Kubernetes host network
// ---------------------------------------------------------------------------

func TestDetect_KubernetesHostNetwork(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx:1.25
`)

	results, err := a.ScanFile("pod.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-008" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Fatalf("expected severity high, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-008 finding for host network")
	}
}

// ---------------------------------------------------------------------------
// IAC-009: Kubernetes allows privilege escalation
// ---------------------------------------------------------------------------

func TestDetect_KubernetesAllowPrivilegeEscalation(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`spec:
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: true
`)

	results, err := a.ScanFile("deploy.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-009" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Fatalf("expected severity critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-009 finding for privilege escalation")
	}
}

// ---------------------------------------------------------------------------
// IAC-010: Kubernetes running as root (runAsUser: 0)
// ---------------------------------------------------------------------------

func TestDetect_KubernetesRunAsRoot(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`spec:
  securityContext:
    runAsUser: 0
  containers:
  - name: app
    image: nginx
`)

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-010" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-010 finding for runAsUser: 0")
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean files
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanDockerfile(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
COPY . /app
USER appuser
CMD ["/app/start"]
`)

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings on clean Dockerfile, got %d", len(results))
	}
}

func TestNoFalsePositives_CleanTerraform(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }
}
`)

	results, err := a.ScanFile("main.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings on clean Terraform, got %d", len(results))
	}
}

func TestNoFalsePositives_CleanKubernetes(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx:1.25
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      privileged: false
`)

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings on clean K8s manifest, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// File pattern filtering: rules should not apply to unrelated files
// ---------------------------------------------------------------------------

func TestFilePatternFiltering_DockerRulesSkipGoFiles(t *testing.T) {
	a := NewAnalyzer()
	// Content that would match Docker rules but in a .go file.
	content := []byte("// USER root\n// FROM ubuntu\n")

	results, err := a.ScanFile("main.go", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings for .go file with Docker rule patterns, got %d", len(results))
	}
}

func TestFilePatternFiltering_TerraformRulesSkipYAML(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`cidr_blocks = ["0.0.0.0/0"]`)

	results, err := a.ScanFile("config.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// YAML files should not trigger Terraform rules (IAC-004, IAC-005, IAC-006)
	for _, f := range results {
		if f.RuleID == "IAC-004" || f.RuleID == "IAC-005" || f.RuleID == "IAC-006" {
			t.Fatalf("terraform rule %s should not apply to .yaml files", f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts integration
// ---------------------------------------------------------------------------

func TestScanArtifacts_MixedIaCFiles(t *testing.T) {
	dir := t.TempDir()

	dockerFile := writeFile(t, dir, "Dockerfile", "FROM ubuntu\nUSER root\nCMD [\"/app\"]\n")
	tfFile := writeFile(t, dir, "main.tf", "cidr_blocks = [\"0.0.0.0/0\"]\n")
	k8sFile := writeFile(t, dir, "pod.yaml", "privileged: true\n")

	artifacts := []discovery.Artifact{
		{Path: "Dockerfile", AbsPath: dockerFile, Type: discovery.Container, Size: 40},
		{Path: "main.tf", AbsPath: tfFile, Type: discovery.Config, Size: 30},
		{Path: "pod.yaml", AbsPath: k8sFile, Type: discovery.Config, Size: 20},
	}

	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allFindings := fs.Findings()
	if len(allFindings) < 3 {
		t.Fatalf("expected at least 3 findings from mixed IaC files, got %d", len(allFindings))
	}

	// Verify findings from different rule categories.
	ruleIDs := make(map[string]bool)
	for _, f := range allFindings {
		ruleIDs[f.RuleID] = true
	}

	// Should have at least one Docker finding and one Terraform finding.
	hasDocker := ruleIDs["IAC-001"] || ruleIDs["IAC-002"] || ruleIDs["IAC-003"]
	hasTerraform := ruleIDs["IAC-004"] || ruleIDs["IAC-005"] || ruleIDs["IAC-006"]
	hasK8s := ruleIDs["IAC-007"] || ruleIDs["IAC-008"] || ruleIDs["IAC-009"] || ruleIDs["IAC-010"]

	if !hasDocker {
		t.Fatal("expected at least one Docker-related finding")
	}
	if !hasTerraform {
		t.Fatal("expected at least one Terraform-related finding")
	}
	if !hasK8s {
		t.Fatal("expected at least one Kubernetes-related finding")
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts with unreadable file
// ---------------------------------------------------------------------------

func TestScanArtifacts_UnreadableFile(t *testing.T) {
	artifacts := []discovery.Artifact{
		{Path: "nonexistent.tf", AbsPath: "/nonexistent/path/file.tf", Type: discovery.Config, Size: 0},
	}

	a := NewAnalyzer()
	_, err := a.ScanArtifacts(artifacts)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

// ---------------------------------------------------------------------------
// Dockerfile extension matching (*.dockerfile)
// ---------------------------------------------------------------------------

func TestDetect_CustomDockerfileExtension(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu\nUSER root\n")

	results, err := a.ScanFile("app.dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-001" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-001 finding for *.dockerfile file")
	}
}

// ---------------------------------------------------------------------------
// Rule count and compilation
// ---------------------------------------------------------------------------

func TestAllIaCRules_Count(t *testing.T) {
	rules := builtinIaCRules()
	if got := len(rules); got != 365 {
		t.Errorf("expected 365 IaC rules, got %d", got)
	}
}

func TestAllIaCRules_Compile(t *testing.T) {
	for _, r := range builtinIaCRules() {
		if r.Pattern == "" {
			t.Errorf("rule %s has empty pattern", r.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// New Dockerfile rules (IAC-022 to IAC-025)
// ---------------------------------------------------------------------------

func TestDetect_DockerSecretInBuildArg(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM node:20\nARG PASSWORD=secret123\nRUN echo $PASSWORD\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-022" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-022 finding for secret in build arg")
	}
}

func TestDetect_CurlPipedToShell(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/install.sh | bash\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-023" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-023 finding for curl piped to shell")
	}
}

func TestDetect_DockerfileSudo(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nRUN sudo apt-get install -y curl\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-024" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-024 finding for sudo in Dockerfile")
	}
}

func TestDetect_DockerfileChmod777(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("FROM ubuntu:22.04\nCOPY --chmod=777 app.sh /app/\n")

	results, err := a.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-025" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-025 finding for chmod 777")
	}
}

// ---------------------------------------------------------------------------
// New Kubernetes rules (IAC-026 to IAC-035)
// ---------------------------------------------------------------------------

func TestDetect_KubernetesHostPID(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-026" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-026 finding for hostPID")
	}
}

func TestDetect_KubernetesHostIPC(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("apiVersion: v1\nkind: Pod\nspec:\n  hostIPC: true\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-027" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-027 finding for hostIPC")
	}
}

func TestDetect_KubernetesDangerousCapability(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("securityContext:\n  capabilities:\n    add:\n      - SYS_ADMIN\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-028" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-028 finding for dangerous capability")
	}
}

func TestDetect_KubernetesWritableRootFS(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("securityContext:\n  readOnlyRootFilesystem: false\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-029" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-029 finding for writable root filesystem")
	}
}

func TestDetect_KubernetesAutoMountSA(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("spec:\n  automountServiceAccountToken: true\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-030" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-030 finding for automount service account token")
	}
}

func TestDetect_KubernetesLatestTag(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("containers:\n  - name: app\n    image: nginx:latest\n")

	results, err := a.ScanFile("deploy.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-031" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-031 finding for latest tag in K8s manifest")
	}
}

func TestDetect_KubernetesClusterAdmin(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("kind: ClusterRoleBinding\nroleRef:\n  name: cluster-admin\n")

	results, err := a.ScanFile("rbac.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-032" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-032 finding for cluster-admin binding")
	}
}

func TestDetect_KubernetesHostPort(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("ports:\n  - containerPort: 8080\n    hostPort: 8080\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-033" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-033 finding for hostPort")
	}
}

func TestDetect_KubernetesLoadBalancer(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("kind: Service\nspec:\n  type: LoadBalancer\n")

	results, err := a.ScanFile("svc.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-034" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-034 finding for LoadBalancer service")
	}
}

func TestDetect_KubernetesRunAsNonRootFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("securityContext:\n  runAsNonRoot: false\n")

	results, err := a.ScanFile("pod.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-035" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-035 finding for runAsNonRoot: false")
	}
}

// ---------------------------------------------------------------------------
// GitHub Actions rules (IAC-011 to IAC-018)
// ---------------------------------------------------------------------------

func TestDetect_GHAPullRequestTarget(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("on:\n  pull_request_target:\n    branches: [main]\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-011" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-011 finding for pull_request_target")
	}
}

func TestDetect_GHAScriptInjection(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("run: echo ${{ github.event.issue.title }}\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-012" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-012 finding for script injection")
	}
}

func TestDetect_GHAUnpinnedAction(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("uses: actions/checkout@v4\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-013" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-013 finding for unpinned action")
	}
}

func TestDetect_GHAWriteAllPermissions(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("permissions: write-all\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-014" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-014 finding for write-all permissions")
	}
}

func TestDetect_GHASecretsInLogs(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("run: echo ${{ secrets.MY_TOKEN }}\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-015" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-015 finding for secrets in logs")
	}
}

func TestDetect_GHASelfHostedRunner(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("runs-on: self-hosted\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-016" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-016 finding for self-hosted runner")
	}
}

func TestDetect_GHADeprecatedSetOutput(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`run: echo "::set-output name=result::value"` + "\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-017" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-017 finding for deprecated set-output")
	}
}

func TestDetect_GHAContinueOnError(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("- name: test\n  continue-on-error: true\n  run: make test\n")

	results, err := a.ScanFile("ci.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-018" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-018 finding for continue-on-error")
	}
}

// ---------------------------------------------------------------------------
// Docker Compose rules (IAC-019 to IAC-021, IAC-049)
// ---------------------------------------------------------------------------

func TestDetect_ComposePrivileged(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("services:\n  app:\n    image: nginx\n    privileged: true\n")

	results, err := a.ScanFile("docker-compose.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-019" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-019 finding for compose privileged")
	}
}

func TestDetect_ComposeHostNetwork(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("services:\n  app:\n    network_mode: host\n")

	results, err := a.ScanFile("docker-compose.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-020" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-020 finding for compose host network")
	}
}

func TestDetect_ComposeDockerSocket(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("services:\n  app:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")

	results, err := a.ScanFile("docker-compose.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-021" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-021 finding for docker socket mount")
	}
}

func TestDetect_ComposeHostPID(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("services:\n  app:\n    pid: host\n")

	results, err := a.ScanFile("docker-compose.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-049" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-049 finding for compose host PID")
	}
}

// ---------------------------------------------------------------------------
// Terraform / Cloud rules (IAC-036 to IAC-045)
// ---------------------------------------------------------------------------

func TestDetect_TerraformRDSPubliclyAccessible(t *testing.T) {
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
		if f.RuleID == "IAC-036" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-036 finding for RDS publicly accessible")
	}
}

func TestDetect_TerraformRDSStorageNotEncrypted(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_db_instance" "default" {
  storage_encrypted = false
}
`)

	results, err := a.ScanFile("rds.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-037" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-037 finding for RDS storage not encrypted")
	}
}

func TestDetect_TerraformCloudTrailDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_cloudtrail" "main" {
  is_multi_region_trail = false
}
`)

	results, err := a.ScanFile("trail.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-038" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-038 finding for CloudTrail disabled")
	}
}

func TestDetect_TerraformIAMWildcard(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`{
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
`)

	results, err := a.ScanFile("policy.json", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-039" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-039 finding for IAM wildcard action")
	}
}

func TestDetect_TerraformS3PublicACL(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
`)

	results, err := a.ScanFile("s3.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-040" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-040 finding for S3 public ACL")
	}
}

func TestDetect_TerraformHTTPProtocol(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_lb_listener" "http" {
  protocol = "HTTP"
}
`)

	results, err := a.ScanFile("alb.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-041" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-041 finding for HTTP protocol")
	}
}

func TestDetect_TerraformAzureHTTPEnabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "azurerm_storage_account" "main" {
  enable_https_traffic_only = false
}
`)

	results, err := a.ScanFile("storage.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-042" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-042 finding for Azure HTTP enabled")
	}
}

func TestDetect_TerraformFirewallAllProtocols(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "google_compute_firewall" "allow_all" {
  allow {
    protocol = "all"
  }
}
`)

	results, err := a.ScanFile("firewall.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-043" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-043 finding for all protocols")
	}
}

func TestDetect_TerraformDefaultVPC(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "aws_default_vpc" "default" {
}
`)

	results, err := a.ScanFile("vpc.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-044" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-044 finding for default VPC")
	}
}

func TestDetect_TerraformLoggingDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`resource "google_container_cluster" "primary" {
  logging_service = "none"
}
`)

	results, err := a.ScanFile("gke.tf", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-045" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-045 finding for logging disabled")
	}
}

// ---------------------------------------------------------------------------
// Helm rules (IAC-046 to IAC-048)
// ---------------------------------------------------------------------------

func TestDetect_HelmTiller(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: tiller-deploy\n")

	results, err := a.ScanFile("tiller.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-046" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-046 finding for Tiller deployment")
	}
}

func TestDetect_HelmDefaultPassword(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("admin_password: supersecret123\n")

	results, err := a.ScanFile("values.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-047" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-047 finding for default admin password")
	}
}

func TestDetect_HelmRBACDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("rbac:\n  create: false\n")

	results, err := a.ScanFile("values.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-048" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-048 finding for RBAC disabled")
	}
}

// ---------------------------------------------------------------------------
// CI/CD general rule (IAC-050)
// ---------------------------------------------------------------------------

func TestDetect_SecurityChecksDisabled(t *testing.T) {
	a := NewAnalyzer()
	content := []byte("security_enabled: false\n")

	results, err := a.ScanFile("config.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-050" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected IAC-050 finding for security checks disabled")
	}
}
