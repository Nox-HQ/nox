package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Kustomize rule count
// ---------------------------------------------------------------------------

func TestKustomizeRules_Count(t *testing.T) {
	rules := builtinKustomizeRules()
	if got := len(rules); got != 15 {
		t.Errorf("expected 15 Kustomize rules, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// IAC-231: image with latest tag
// ---------------------------------------------------------------------------

func TestDetect_KustomizeImageLatest(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
images:
  - name: myapp
    image: nginx:latest
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-231" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-231 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-232: namespace: default
// ---------------------------------------------------------------------------

func TestDetect_KustomizeDefaultNamespace(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: default
resources:
  - deployment.yaml
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-232" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-232 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-235: secretGenerator with inline literals
// ---------------------------------------------------------------------------

func TestDetect_KustomizeSecretGeneratorLiterals(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)literals:\s*\n\s*-\s*\w+=
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: my-secret
    literals:
      - DB_PASSWORD=supersecret
      - API_KEY=abc123
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-235" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-235 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-238: count: 1 (single replica, no HA)
// ---------------------------------------------------------------------------

func TestDetect_KustomizeSingleReplica(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)count:\s*1\b
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
replicas:
  - name: my-deployment
    count: 1
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-238" {
			found = true
			if f.Severity != findings.SeverityLow {
				t.Errorf("expected severity low, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-238 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-242: Kustomize references parent directory resources
// ---------------------------------------------------------------------------

func TestDetect_KustomizeParentDirectoryResources(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)resources:\s*\n\s*-\s*\.\.
	// Keywords: ["resources", ".."] (all lowercase, passes keyword filter)
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-242" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-242 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-237: privileged: true in Kustomize overlay
// ---------------------------------------------------------------------------

func TestDetect_KustomizePrivilegedContainer(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patchesStrategicMerge:
  - |-
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: myapp
    spec:
      template:
        spec:
          containers:
            - name: myapp
              securityContext:
                privileged: true
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-237" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-237 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-244: Kustomize image override uses latest tag
// ---------------------------------------------------------------------------

func TestDetect_KustomizeImageOverrideLatest(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)images:\s*\n\s*-\s*name:.*\n\s*newTag:\s*['"]?latest
	// Keywords: ["newTag", "latest"] -- "latest" is lowercase, passes keyword filter.
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: myapp
    newTag: latest
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-244" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-244 to be detected")
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean Kustomize content
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanKustomize(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: production
resources:
  - deployment.yaml
  - service.yaml
images:
  - name: myapp
    newTag: v1.2.3
`)

	results, err := a.ScanFile("kustomization.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Filter to only Kustomize rules (IAC-231 to IAC-245).
	for _, f := range results {
		if f.RuleID >= "IAC-231" && f.RuleID <= "IAC-245" {
			t.Errorf("unexpected Kustomize finding %s on clean content", f.RuleID)
		}
	}
}
