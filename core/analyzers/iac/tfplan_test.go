package iac

import (
	"testing"
)

func TestScanTerraformPlanContent_PublicCIDR(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_security_group.allow_all",
				"type": "aws_security_group_rule",
				"change": {
					"actions": ["create"],
					"after": {
						"cidr_blocks": ["0.0.0.0/0"],
						"from_port": 0,
						"to_port": 65535
					}
				}
			}
		]
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-004" {
			found = true
			if f.Metadata["source"] != "terraform-plan" {
				t.Error("expected terraform-plan source metadata")
			}
		}
	}
	if !found {
		t.Error("expected IAC-004 finding for public CIDR")
	}
}

func TestScanTerraformPlanContent_PubliclyAccessibleDB(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_db_instance.main",
				"type": "aws_db_instance",
				"change": {
					"actions": ["create"],
					"after": {
						"publicly_accessible": true,
						"storage_encrypted": false
					}
				}
			}
		]
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ruleIDs := make(map[string]bool)
	for _, f := range fs.Findings() {
		ruleIDs[f.RuleID] = true
	}

	if !ruleIDs["IAC-036"] {
		t.Error("expected IAC-036 for publicly accessible DB")
	}
	if !ruleIDs["IAC-037"] {
		t.Error("expected IAC-037 for unencrypted storage")
	}
}

func TestScanTerraformPlanContent_SSHPort(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_security_group_rule.ssh",
				"type": "aws_security_group_rule",
				"change": {
					"actions": ["create"],
					"after": {
						"from_port": 22,
						"to_port": 22,
						"cidr_blocks": ["10.0.0.0/8"]
					}
				}
			}
		]
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-006" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-006 for SSH port")
	}
}

func TestScanTerraformPlanContent_PublicACL(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.data",
				"type": "aws_s3_bucket",
				"change": {
					"actions": ["create"],
					"after": {
						"acl": "public-read"
					}
				}
			}
		]
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-040" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-040 for public S3 ACL")
	}
}

func TestScanTerraformPlanContent_Empty(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": []
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fs.Findings()) != 0 {
		t.Errorf("expected 0 findings for empty plan, got %d", len(fs.Findings()))
	}
}

func TestScanTerraformPlanContent_InvalidJSON(t *testing.T) {
	_, err := scanTerraformPlanContent([]byte(`{invalid}`), "plan.json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestScanTerraformPlan_FileNotFound(t *testing.T) {
	_, err := ScanTerraformPlan("/nonexistent/plan.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestScanTerraformPlanContent_PlannedValues(t *testing.T) {
	// Test scanning from planned_values (not resource_changes).
	planJSON := []byte(`{
		"planned_values": {
			"root_module": {
				"resources": [
					{
						"address": "aws_s3_bucket.logs",
						"type": "aws_s3_bucket",
						"name": "logs",
						"values": {
							"acl": "public-read-write"
						}
					}
				]
			}
		},
		"resource_changes": []
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-040" {
			found = true
		}
	}
	if !found {
		t.Error("expected IAC-040 from planned_values scan")
	}
}
