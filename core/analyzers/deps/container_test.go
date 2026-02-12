package deps

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func TestParseDockerfile_SimpleImages(t *testing.T) {
	content := []byte(`FROM ubuntu:22.04
RUN apt-get update
FROM python:3.11-slim AS builder
COPY . /app
FROM node:18
CMD ["node", "app.js"]
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(pkgs), pkgs)
	}

	expected := []Package{
		{Name: "ubuntu", Version: "22.04", Ecosystem: "docker"},
		{Name: "python", Version: "3.11-slim", Ecosystem: "docker"},
		{Name: "node", Version: "18", Ecosystem: "docker"},
	}

	for i, exp := range expected {
		if pkgs[i].Name != exp.Name {
			t.Errorf("package[%d].Name: got %q, want %q", i, pkgs[i].Name, exp.Name)
		}
		if pkgs[i].Version != exp.Version {
			t.Errorf("package[%d].Version: got %q, want %q", i, pkgs[i].Version, exp.Version)
		}
		if pkgs[i].Ecosystem != exp.Ecosystem {
			t.Errorf("package[%d].Ecosystem: got %q, want %q", i, pkgs[i].Ecosystem, exp.Ecosystem)
		}
	}
}

func TestParseDockerfile_RegistryImage(t *testing.T) {
	content := []byte(`FROM registry.example.com/myimage:v1.2
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "registry.example.com/myimage" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "registry.example.com/myimage")
	}
	if pkgs[0].Version != "v1.2" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "v1.2")
	}
}

func TestParseDockerfile_RegistryWithPort(t *testing.T) {
	content := []byte(`FROM registry.example.com:5000/myimage:v2.0
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "registry.example.com:5000/myimage" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "registry.example.com:5000/myimage")
	}
	if pkgs[0].Version != "v2.0" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "v2.0")
	}
}

func TestParseDockerfile_UntaggedImage(t *testing.T) {
	content := []byte(`FROM ubuntu
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "ubuntu" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "ubuntu")
	}
	if pkgs[0].Version != "latest" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "latest")
	}
}

func TestParseDockerfile_DigestPin(t *testing.T) {
	content := []byte(`FROM ubuntu@sha256:abcdef1234567890
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "ubuntu" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "ubuntu")
	}
	if pkgs[0].Version != "sha256:abcdef1234567890" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "sha256:abcdef1234567890")
	}
}

func TestParseDockerfile_SkipScratch(t *testing.T) {
	content := []byte(`FROM golang:1.21 AS builder
RUN go build -o app
FROM scratch
COPY --from=builder /app /app
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package (scratch skipped), got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "golang" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "golang")
	}
}

func TestParseDockerfile_SkipScratchCaseInsensitive(t *testing.T) {
	content := []byte(`FROM SCRATCH
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages (SCRATCH skipped), got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseDockerfile_SkipVariable(t *testing.T) {
	content := []byte(`ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}
FROM $BASE_IMAGE
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages (variables skipped), got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseDockerfile_Comments(t *testing.T) {
	content := []byte(`# This is a comment
# FROM fake:image
FROM alpine:3.18
# Another comment
RUN echo hello
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "alpine" {
		t.Errorf("Name: got %q, want %q", pkgs[0].Name, "alpine")
	}
	if pkgs[0].Version != "3.18" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "3.18")
	}
}

func TestParseDockerfile_PlatformFlag(t *testing.T) {
	content := []byte(`FROM --platform=linux/amd64 golang:1.21-alpine AS builder
FROM --platform=linux/arm64 node:20
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Name != "golang" {
		t.Errorf("package[0].Name: got %q, want %q", pkgs[0].Name, "golang")
	}
	if pkgs[0].Version != "1.21-alpine" {
		t.Errorf("package[0].Version: got %q, want %q", pkgs[0].Version, "1.21-alpine")
	}

	if pkgs[1].Name != "node" {
		t.Errorf("package[1].Name: got %q, want %q", pkgs[1].Name, "node")
	}
	if pkgs[1].Version != "20" {
		t.Errorf("package[1].Version: got %q, want %q", pkgs[1].Version, "20")
	}
}

func TestParseDockerfile_MultiStage(t *testing.T) {
	content := []byte(`FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}

	expected := []Package{
		{Name: "golang", Version: "1.21-alpine", Ecosystem: "docker"},
		{Name: "alpine", Version: "3.18", Ecosystem: "docker"},
	}

	for i, exp := range expected {
		if pkgs[i].Name != exp.Name {
			t.Errorf("package[%d].Name: got %q, want %q", i, pkgs[i].Name, exp.Name)
		}
		if pkgs[i].Version != exp.Version {
			t.Errorf("package[%d].Version: got %q, want %q", i, pkgs[i].Version, exp.Version)
		}
	}
}

func TestParseDockerfile_Empty(t *testing.T) {
	pkgs, err := ParseDockerfile([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages from empty input, got %d", len(pkgs))
	}
}

func TestParseDockerfile_OnlyComments(t *testing.T) {
	content := []byte(`# syntax=docker/dockerfile:1
# This is just comments
# No FROM instructions here
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseDockerfile_LatestExplicit(t *testing.T) {
	content := []byte(`FROM nginx:latest
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %+v", len(pkgs), pkgs)
	}

	if pkgs[0].Version != "latest" {
		t.Errorf("Version: got %q, want %q", pkgs[0].Version, "latest")
	}
}

func TestParseDockerfile_CaseInsensitiveFrom(t *testing.T) {
	content := []byte(`from alpine:3.18
FROM nginx:1.25
`)

	pkgs, err := ParseDockerfile(content)
	if err != nil {
		t.Fatalf("ParseDockerfile returned error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref     string
		name    string
		version string
	}{
		{"ubuntu:22.04", "ubuntu", "22.04"},
		{"ubuntu", "ubuntu", "latest"},
		{"node:18-alpine", "node", "18-alpine"},
		{"node@sha256:abc123", "node", "sha256:abc123"},
		{"registry.example.com/myimage:v1.2", "registry.example.com/myimage", "v1.2"},
		{"registry.example.com:5000/myimage:v2.0", "registry.example.com:5000/myimage", "v2.0"},
		{"registry.example.com:5000/myimage", "registry.example.com:5000/myimage", "latest"},
		{"ghcr.io/owner/image:sha-abc123", "ghcr.io/owner/image", "sha-abc123"},
		{"nginx", "nginx", "latest"},
		{"nginx:latest", "nginx", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			name, version := parseImageRef(tt.ref)
			if name != tt.name {
				t.Errorf("name: got %q, want %q", name, tt.name)
			}
			if version != tt.version {
				t.Errorf("version: got %q, want %q", version, tt.version)
			}
		})
	}
}

func TestIsDockerfile(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"Dockerfile", true},
		{"Dockerfile.production", true},
		{"Dockerfile.dev", true},
		{"app.dockerfile", true},
		{"App.Dockerfile", true},
		{"build.dockerfile", true},
		{"docker-compose.yml", false},
		{"main.go", false},
		{"README.md", false},
		{"path/to/Dockerfile", true},
		{"path/to/Dockerfile.staging", true},
		{"path/to/app.dockerfile", true},
		{"path/to/docker-compose.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isDockerfile(tt.filename)
			if got != tt.want {
				t.Errorf("isDockerfile(%q): got %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestImageIsPinnedToDigest(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"sha256:abcdef1234567890", true},
		{"22.04", false},
		{"latest", false},
		{"3.18-alpine", false},
		{"sha256:", true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := imageIsPinnedToDigest(tt.version)
			if got != tt.want {
				t.Errorf("imageIsPinnedToDigest(%q): got %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestImageUsesLatestTag(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"latest", true},
		{"22.04", false},
		{"3.18", false},
		{"sha256:abc", false},
		{"1.21-alpine", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := imageUsesLatestTag(tt.version)
			if got != tt.want {
				t.Errorf("imageUsesLatestTag(%q): got %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestDockerfileFromLines(t *testing.T) {
	content := []byte(`# Comment
FROM ubuntu:22.04
RUN apt-get update
FROM scratch
FROM python:3.11 AS builder
COPY . /app
FROM ${BASE_IMAGE}
FROM node:18
`)

	lines := dockerfileFromLines(content)

	// scratch and ${BASE_IMAGE} are skipped, so we expect lines for:
	// ubuntu:22.04 (line 2), python:3.11 (line 5), node:18 (line 8)
	expected := []int{2, 5, 8}

	if len(lines) != len(expected) {
		t.Fatalf("expected %d FROM lines, got %d: %v", len(expected), len(lines), lines)
	}

	for i, exp := range expected {
		if lines[i] != exp {
			t.Errorf("fromLines[%d]: got %d, want %d", i, lines[i], exp)
		}
	}
}

func TestScanArtifacts_Dockerfile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a Dockerfile with mixed pinning scenarios.
	dockerfileContent := []byte(`FROM ubuntu:22.04
RUN apt-get update
FROM node
FROM alpine@sha256:abcdef1234567890
`)
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, dockerfileContent, 0o644); err != nil {
		t.Fatalf("writing Dockerfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "Dockerfile",
			AbsPath: dockerfilePath,
			Type:    discovery.Container,
			Size:    int64(len(dockerfileContent)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// Should have 3 packages: ubuntu:22.04, node:latest, alpine@sha256:...
	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 3 {
		t.Fatalf("expected 3 docker packages, got %d: %+v", len(dockerPkgs), dockerPkgs)
	}

	// Sort by name for deterministic checks.
	sort.Slice(dockerPkgs, func(i, j int) bool {
		return dockerPkgs[i].Name < dockerPkgs[j].Name
	})

	expectedPkgs := []Package{
		{Name: "alpine", Version: "sha256:abcdef1234567890", Ecosystem: "docker"},
		{Name: "node", Version: "latest", Ecosystem: "docker"},
		{Name: "ubuntu", Version: "22.04", Ecosystem: "docker"},
	}

	for i, exp := range expectedPkgs {
		if dockerPkgs[i].Name != exp.Name {
			t.Errorf("docker package[%d].Name: got %q, want %q", i, dockerPkgs[i].Name, exp.Name)
		}
		if dockerPkgs[i].Version != exp.Version {
			t.Errorf("docker package[%d].Version: got %q, want %q", i, dockerPkgs[i].Version, exp.Version)
		}
	}

	// Check findings.
	allFindings := fs.Findings()

	// Count findings by rule.
	ruleCount := make(map[string]int)
	for _, f := range allFindings {
		ruleCount[f.RuleID]++
	}

	// CONT-001: ubuntu:22.04 (not pinned to digest) and node:latest (not pinned to digest).
	// alpine@sha256:... IS pinned, so no CONT-001 for it.
	if ruleCount["CONT-001"] != 2 {
		t.Errorf("expected 2 CONT-001 findings, got %d", ruleCount["CONT-001"])
	}

	// CONT-002: node:latest uses latest tag.
	if ruleCount["CONT-002"] != 1 {
		t.Errorf("expected 1 CONT-002 finding, got %d", ruleCount["CONT-002"])
	}
}

func TestScanArtifacts_DockerfileVariant(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a Dockerfile.production file.
	content := []byte(`FROM nginx:1.25-alpine
COPY dist/ /usr/share/nginx/html/
`)
	path := filepath.Join(tmpDir, "Dockerfile.production")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing Dockerfile.production: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "Dockerfile.production",
			AbsPath: path,
			Type:    discovery.Container,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 1 {
		t.Fatalf("expected 1 docker package, got %d: %+v", len(dockerPkgs), dockerPkgs)
	}

	if dockerPkgs[0].Name != "nginx" {
		t.Errorf("Name: got %q, want %q", dockerPkgs[0].Name, "nginx")
	}
	if dockerPkgs[0].Version != "1.25-alpine" {
		t.Errorf("Version: got %q, want %q", dockerPkgs[0].Version, "1.25-alpine")
	}

	// Should have CONT-001 (not pinned to digest) but no CONT-002 (has explicit tag).
	allFindings := fs.Findings()
	ruleCount := make(map[string]int)
	for _, f := range allFindings {
		ruleCount[f.RuleID]++
	}

	if ruleCount["CONT-001"] != 1 {
		t.Errorf("expected 1 CONT-001 finding, got %d", ruleCount["CONT-001"])
	}
	if ruleCount["CONT-002"] != 0 {
		t.Errorf("expected 0 CONT-002 findings, got %d", ruleCount["CONT-002"])
	}
}

func TestScanArtifacts_DockerfilePinnedDigest(t *testing.T) {
	tmpDir := t.TempDir()

	// A fully pinned Dockerfile should produce no container findings.
	content := []byte(`FROM ubuntu@sha256:aaaa1111
FROM node@sha256:bbbb2222
`)
	path := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing Dockerfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "Dockerfile",
			AbsPath: path,
			Type:    discovery.Container,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 2 {
		t.Fatalf("expected 2 docker packages, got %d", len(dockerPkgs))
	}

	// No container findings: all images are pinned to digest.
	for _, f := range fs.Findings() {
		if f.RuleID == "CONT-001" || f.RuleID == "CONT-002" {
			t.Errorf("unexpected finding %s for fully pinned Dockerfile: %s", f.RuleID, f.Message)
		}
	}
}

func TestScanArtifacts_NonDockerfileContainer(t *testing.T) {
	tmpDir := t.TempDir()

	// docker-compose.yml is a Container artifact but not a Dockerfile.
	// It should not be parsed by the container scanner.
	content := []byte(`version: '3'
services:
  web:
    image: nginx:latest
`)
	path := filepath.Join(tmpDir, "docker-compose.yml")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing docker-compose.yml: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "docker-compose.yml",
			AbsPath: path,
			Type:    discovery.Container,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, _, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 0 {
		t.Fatalf("expected 0 docker packages from compose file, got %d: %+v", len(dockerPkgs), dockerPkgs)
	}
}

func TestScanArtifacts_MixedLockfileAndDockerfile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a go.sum lockfile.
	goSumContent := []byte("golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n")
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, goSumContent, 0o644); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}

	// Write a Dockerfile.
	dockerfileContent := []byte(`FROM golang:1.21
RUN go build -o app
`)
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, dockerfileContent, 0o644); err != nil {
		t.Fatalf("writing Dockerfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "go.sum",
			AbsPath: goSumPath,
			Type:    discovery.Lockfile,
			Size:    int64(len(goSumContent)),
		},
		{
			Path:    "Dockerfile",
			AbsPath: dockerfilePath,
			Type:    discovery.Container,
			Size:    int64(len(dockerfileContent)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, _, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	allPkgs := inventory.Packages()
	if len(allPkgs) != 2 {
		t.Fatalf("expected 2 packages (1 go + 1 docker), got %d: %+v", len(allPkgs), allPkgs)
	}

	goPkgs := inventory.ByEcosystem("go")
	if len(goPkgs) != 1 {
		t.Errorf("expected 1 go package, got %d", len(goPkgs))
	}

	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 1 {
		t.Errorf("expected 1 docker package, got %d", len(dockerPkgs))
	}
}

func TestScanArtifacts_DockerfileSuffix(t *testing.T) {
	tmpDir := t.TempDir()

	content := []byte(`FROM python:3.11
CMD ["python", "app.py"]
`)
	path := filepath.Join(tmpDir, "app.dockerfile")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing app.dockerfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "app.dockerfile",
			AbsPath: path,
			Type:    discovery.Container,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	inventory, _, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	dockerPkgs := inventory.ByEcosystem("docker")
	if len(dockerPkgs) != 1 {
		t.Fatalf("expected 1 docker package, got %d: %+v", len(dockerPkgs), dockerPkgs)
	}

	if dockerPkgs[0].Name != "python" {
		t.Errorf("Name: got %q, want %q", dockerPkgs[0].Name, "python")
	}
}

func TestScanArtifacts_DockerfileFindingLocations(t *testing.T) {
	tmpDir := t.TempDir()

	content := []byte(`# Build stage
FROM golang:1.21 AS builder
RUN go build -o app

# Runtime stage
FROM alpine
COPY --from=builder /app /app
`)
	path := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing Dockerfile: %v", err)
	}

	artifacts := []discovery.Artifact{
		{
			Path:    "Dockerfile",
			AbsPath: path,
			Type:    discovery.Container,
			Size:    int64(len(content)),
		},
	}

	analyzer := NewAnalyzer(WithOSVDisabled())
	_, fs, err := analyzer.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts returned error: %v", err)
	}

	// golang:1.21 is on line 2 (not pinned to digest -> CONT-001).
	// alpine (no tag) is on line 6 (CONT-001 and CONT-002).
	allFindings := fs.Findings()

	// Find CONT-002 for alpine.
	var cont002Found bool
	for _, f := range allFindings {
		if f.RuleID == "CONT-002" {
			cont002Found = true
			if f.Location.StartLine != 6 {
				t.Errorf("CONT-002 StartLine: got %d, want 6", f.Location.StartLine)
			}
			if f.Location.FilePath != "Dockerfile" {
				t.Errorf("CONT-002 FilePath: got %q, want %q", f.Location.FilePath, "Dockerfile")
			}
		}
	}
	if !cont002Found {
		t.Error("expected CONT-002 finding for untagged alpine image")
	}
}

func TestContainerRulesRegistered(t *testing.T) {
	analyzer := NewAnalyzer(WithOSVDisabled())
	rs := analyzer.Rules()

	cont001, ok := rs.ByID("CONT-001")
	if !ok {
		t.Fatal("CONT-001 rule not found in rule set")
	}
	if cont001.Severity != "medium" {
		t.Errorf("CONT-001 severity: got %q, want %q", cont001.Severity, "medium")
	}

	cont002, ok := rs.ByID("CONT-002")
	if !ok {
		t.Fatal("CONT-002 rule not found in rule set")
	}
	if cont002.Severity != "high" {
		t.Errorf("CONT-002 severity: got %q, want %q", cont002.Severity, "high")
	}

	// Verify tags.
	containerRules := rs.ByTag("container")
	if len(containerRules) != 2 {
		t.Errorf("expected 2 container rules, got %d", len(containerRules))
	}
}
