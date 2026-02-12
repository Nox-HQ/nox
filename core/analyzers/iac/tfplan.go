// Package iac implements Infrastructure-as-Code security scanning.
package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// tfPlan is the minimal structure for terraform show -json output.
type tfPlan struct {
	PlannedValues struct {
		RootModule struct {
			Resources []tfPlanResource `json:"resources"`
		} `json:"root_module"`
	} `json:"planned_values"`
	ResourceChanges []tfResourceChange `json:"resource_changes"`
}

// tfPlanResource represents a resource in the planned state.
type tfPlanResource struct {
	Address string                 `json:"address"`
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Values  map[string]interface{} `json:"values"`
}

// tfResourceChange represents a resource change in the plan.
type tfResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Change  struct {
		Actions []string               `json:"actions"`
		After   map[string]interface{} `json:"after"`
	} `json:"change"`
}

// ScanTerraformPlan parses a terraform plan JSON file and checks planned
// resource values against IaC security rules.
func ScanTerraformPlan(planPath string) (*findings.FindingSet, error) {
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("reading terraform plan %s: %w", planPath, err)
	}

	return scanTerraformPlanContent(data, planPath)
}

// scanTerraformPlanContent parses and scans terraform plan JSON content.
func scanTerraformPlanContent(content []byte, path string) (*findings.FindingSet, error) {
	var plan tfPlan
	if err := json.Unmarshal(content, &plan); err != nil {
		return nil, fmt.Errorf("parsing terraform plan JSON: %w", err)
	}

	fs := findings.NewFindingSet()

	// Check resource changes (after-state).
	for _, rc := range plan.ResourceChanges {
		if rc.Change.After == nil {
			continue
		}
		checkTfResourceValues(fs, rc.Address, rc.Type, rc.Change.After, path)
	}

	// Also check planned values for resources without changes.
	for _, res := range plan.PlannedValues.RootModule.Resources {
		if res.Values == nil {
			continue
		}
		checkTfResourceValues(fs, res.Address, res.Type, res.Values, path)
	}

	fs.Deduplicate()
	return fs, nil
}

// checkTfResourceValues checks a resource's planned values against known security patterns.
func checkTfResourceValues(fs *findings.FindingSet, address, resourceType string, values map[string]interface{}, path string) {
	// Check for public CIDR blocks.
	if cidrBlocks, ok := getStringSlice(values, "cidr_blocks"); ok {
		for _, cidr := range cidrBlocks {
			if cidr == "0.0.0.0/0" {
				fs.Add(findings.Finding{
					RuleID:     "IAC-004",
					Severity:   findings.SeverityHigh,
					Confidence: findings.ConfidenceMedium,
					Location:   findings.Location{FilePath: path, StartLine: 1},
					Message:    fmt.Sprintf("Planned resource %s allows public access (0.0.0.0/0)", address),
					Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
				})
			}
		}
	}

	// Check for encryption disabled.
	if val, ok := getBool(values, "encrypted"); ok && !val {
		fs.Add(findings.Finding{
			RuleID:     "IAC-005",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceLow,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s has encryption disabled", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}

	// Check for publicly accessible databases.
	if val, ok := getBool(values, "publicly_accessible"); ok && val {
		fs.Add(findings.Finding{
			RuleID:     "IAC-036",
			Severity:   findings.SeverityCritical,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s is publicly accessible", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}

	// Check for storage encryption disabled.
	if val, ok := getBool(values, "storage_encrypted"); ok && !val {
		fs.Add(findings.Finding{
			RuleID:     "IAC-037",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s has storage encryption disabled", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}

	// Check for HTTP protocol on load balancers.
	if proto, ok := getString(values, "protocol"); ok && strings.EqualFold(proto, "HTTP") {
		if strings.Contains(resourceType, "listener") || strings.Contains(resourceType, "lb") {
			fs.Add(findings.Finding{
				RuleID:     "IAC-041",
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceMedium,
				Location:   findings.Location{FilePath: path, StartLine: 1},
				Message:    fmt.Sprintf("Planned resource %s uses HTTP instead of HTTPS", address),
				Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
			})
		}
	}

	// Check for public S3 ACLs.
	if acl, ok := getString(values, "acl"); ok {
		if acl == "public-read" || acl == "public-read-write" {
			fs.Add(findings.Finding{
				RuleID:     "IAC-040",
				Severity:   findings.SeverityCritical,
				Confidence: findings.ConfidenceHigh,
				Location:   findings.Location{FilePath: path, StartLine: 1},
				Message:    fmt.Sprintf("Planned resource %s has public ACL: %s", address, acl),
				Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
			})
		}
	}

	// Check for SSH port 22.
	if port, ok := getFloat(values, "from_port"); ok && port == 22 {
		fs.Add(findings.Finding{
			RuleID:     "IAC-006",
			Severity:   findings.SeverityCritical,
			Confidence: findings.ConfidenceMedium,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s allows SSH access (port 22)", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}

	// Check for HTTPS traffic only disabled (Azure).
	if val, ok := getBool(values, "enable_https_traffic_only"); ok && !val {
		fs.Add(findings.Finding{
			RuleID:     "IAC-042",
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s allows HTTP traffic", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}

	// Check for privileged containers.
	if val, ok := getBool(values, "privileged"); ok && val {
		fs.Add(findings.Finding{
			RuleID:     "IAC-007",
			Severity:   findings.SeverityCritical,
			Confidence: findings.ConfidenceHigh,
			Location:   findings.Location{FilePath: path, StartLine: 1},
			Message:    fmt.Sprintf("Planned resource %s runs as privileged", address),
			Metadata:   map[string]string{"resource": address, "source": "terraform-plan"},
		})
	}
}

// Helper functions for extracting typed values from map[string]interface{}.

func getString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func getBool(m map[string]interface{}, key string) (val, ok bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func getFloat(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}

func getStringSlice(m map[string]interface{}, key string) ([]string, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result, len(result) > 0
}
