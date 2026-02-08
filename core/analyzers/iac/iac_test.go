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
