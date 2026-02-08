// Package iac implements Infrastructure-as-Code security scanning. It wraps
// the core/rules engine with built-in rules that detect common IaC
// misconfigurations in Dockerfiles, Terraform files, and Kubernetes manifests.
package iac

import (
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer wraps a rules.Engine pre-loaded with IaC security rules.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in IaC security rules loaded
// programmatically. Rules are scoped to specific file types via FilePatterns.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()

	builtinRules := []rules.Rule{
		// -----------------------------------------------------------------
		// Dockerfile rules
		// -----------------------------------------------------------------
		{
			ID:           "IAC-001",
			Version:      "1.0",
			Description:  "Dockerfile runs as root user",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?im)^\s*USER\s+root\s*$`,
			FilePatterns: []string{"Dockerfile", "*.dockerfile"},
			Tags:         []string{"iac", "docker", "privilege"},
			Metadata:     map[string]string{"cwe": "CWE-250"},
		},
		{
			ID:           "IAC-002",
			Version:      "1.0",
			Description:  "Dockerfile uses unpinned base image (latest or no tag)",
			Severity:     findings.SeverityMedium,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?im)^\s*FROM\s+[a-zA-Z0-9._/-]+\s*$|(?im)^\s*FROM\s+\S+:latest\b`,
			FilePatterns: []string{"Dockerfile", "*.dockerfile"},
			Tags:         []string{"iac", "docker", "supply-chain"},
			Metadata:     map[string]string{"cwe": "CWE-829"},
		},
		{
			ID:           "IAC-003",
			Version:      "1.0",
			Description:  "Dockerfile uses ADD instead of COPY",
			Severity:     findings.SeverityLow,
			Confidence:   findings.ConfidenceHigh,
			MatcherType:  "regex",
			Pattern:      `(?im)^\s*ADD\s+`,
			FilePatterns: []string{"Dockerfile", "*.dockerfile"},
			Tags:         []string{"iac", "docker", "best-practice"},
		},

		// -----------------------------------------------------------------
		// Terraform rules
		// -----------------------------------------------------------------
		{
			ID:           "IAC-004",
			Version:      "1.0",
			Description:  "Terraform resource allows public access (0.0.0.0/0)",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?i)(cidr_blocks|ingress_cidr|source_ranges)\s*=\s*\[?\s*"0\.0\.0\.0/0"`,
			FilePatterns: []string{"*.tf", "*.tfvars"},
			Tags:         []string{"iac", "terraform", "network"},
			Metadata:     map[string]string{"cwe": "CWE-284"},
		},
		{
			ID:           "IAC-005",
			Version:      "1.0",
			Description:  "Terraform S3 bucket missing encryption configuration",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceLow,
			MatcherType:  "regex",
			Pattern:      `(?i)encrypt\w*\s*=\s*(false|"false")`,
			FilePatterns: []string{"*.tf", "*.tfvars"},
			Tags:         []string{"iac", "terraform", "encryption"},
			Metadata:     map[string]string{"cwe": "CWE-311"},
		},
		{
			ID:           "IAC-006",
			Version:      "1.0",
			Description:  "Terraform security group allows unrestricted SSH access",
			Severity:     findings.SeverityCritical,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?i)(from_port|to_port)\s*=\s*22`,
			FilePatterns: []string{"*.tf"},
			Tags:         []string{"iac", "terraform", "network"},
			Metadata:     map[string]string{"cwe": "CWE-284"},
		},

		// -----------------------------------------------------------------
		// Kubernetes rules
		// -----------------------------------------------------------------
		{
			ID:           "IAC-007",
			Version:      "1.0",
			Description:  "Kubernetes pod running as privileged",
			Severity:     findings.SeverityCritical,
			Confidence:   findings.ConfidenceHigh,
			MatcherType:  "regex",
			Pattern:      `(?i)privileged\s*:\s*true`,
			FilePatterns: []string{"*.yaml", "*.yml"},
			Tags:         []string{"iac", "kubernetes", "privilege"},
			Metadata:     map[string]string{"cwe": "CWE-250"},
		},
		{
			ID:           "IAC-008",
			Version:      "1.0",
			Description:  "Kubernetes pod uses host network",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceHigh,
			MatcherType:  "regex",
			Pattern:      `(?i)hostNetwork\s*:\s*true`,
			FilePatterns: []string{"*.yaml", "*.yml"},
			Tags:         []string{"iac", "kubernetes", "network"},
			Metadata:     map[string]string{"cwe": "CWE-284"},
		},
		{
			ID:           "IAC-009",
			Version:      "1.0",
			Description:  "Kubernetes pod allows privilege escalation",
			Severity:     findings.SeverityCritical,
			Confidence:   findings.ConfidenceHigh,
			MatcherType:  "regex",
			Pattern:      `(?i)allowPrivilegeEscalation\s*:\s*true`,
			FilePatterns: []string{"*.yaml", "*.yml"},
			Tags:         []string{"iac", "kubernetes", "privilege"},
			Metadata:     map[string]string{"cwe": "CWE-250"},
		},
		{
			ID:           "IAC-010",
			Version:      "1.0",
			Description:  "Kubernetes pod running as root (runAsUser: 0)",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceHigh,
			MatcherType:  "regex",
			Pattern:      `(?im)runAsUser\s*:\s*0\s*$`,
			FilePatterns: []string{"*.yaml", "*.yml"},
			Tags:         []string{"iac", "kubernetes", "privilege"},
			Metadata:     map[string]string{"cwe": "CWE-250"},
		},
	}

	for _, r := range builtinRules {
		rs.Add(r)
	}

	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any IaC-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// ScanArtifacts reads each artifact file from disk, scans it for IaC
// misconfigurations, and collects all findings into a deduplicated FindingSet.
func (a *Analyzer) ScanArtifacts(artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, artifact := range artifacts {
		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		for _, f := range results {
			fs.Add(f)
		}
	}

	fs.Deduplicate()
	return fs, nil
}
