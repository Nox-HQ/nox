package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// --- IAC-366: Public subnet + unrestricted security group in same VPC ---

func TestCrossResource_PublicSubnetOpenSG(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_vpc.main",
				"type": "aws_vpc",
				"change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}}
			},
			{
				"address": "aws_subnet.public",
				"type": "aws_subnet",
				"change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}
			},
			{
				"address": "aws_security_group.open",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 65535, "protocol": "-1"}]
				}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}},
					{"address": "aws_security_group.open", "type": "aws_security_group", "name": "open",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", true, "expected IAC-366 for public subnet + open SG")
	assertMetadata(t, fs, "IAC-366", "source", "terraform-plan-graph")
}

func TestCrossResource_PublicSubnetOpenSG_DifferentVPCs(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_subnet.public",
				"type": "aws_subnet",
				"change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}
			},
			{
				"address": "aws_security_group.open",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 65535, "protocol": "-1"}]
				}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.prod.id"]}}},
					{"address": "aws_security_group.open", "type": "aws_security_group", "name": "open",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.staging.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", false, "should not fire when subnet and SG are in different VPCs")
}

func TestCrossResource_PublicSubnetOpenSG_PrivateSubnet(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_subnet.private",
				"type": "aws_subnet",
				"change": {"actions": ["create"], "after": {"map_public_ip_on_launch": false}}
			},
			{
				"address": "aws_security_group.open",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 65535, "protocol": "-1"}]
				}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.private", "type": "aws_subnet", "name": "private",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group.open", "type": "aws_security_group", "name": "open",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", false, "should not fire for private subnet")
}

func TestCrossResource_PublicSubnetOpenSG_SeparateRule(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_subnet.public",
				"type": "aws_subnet",
				"change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}
			},
			{
				"address": "aws_security_group.web",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {}}
			},
			{
				"address": "aws_security_group_rule.allow_all",
				"type": "aws_security_group_rule",
				"change": {"actions": ["create"], "after": {
					"type": "ingress",
					"cidr_blocks": ["0.0.0.0/0"],
					"from_port": 0,
					"to_port": 65535
				}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group.web", "type": "aws_security_group", "name": "web",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group_rule.allow_all", "type": "aws_security_group_rule", "name": "allow_all",
					 "expressions": {"security_group_id": {"references": ["aws_security_group.web.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", true, "should detect via separate aws_security_group_rule")
}

func TestCrossResource_PublicSubnetOpenSG_IPv6(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_subnet.public",
				"type": "aws_subnet",
				"change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}
			},
			{
				"address": "aws_security_group.open_v6",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"ipv6_cidr_blocks": ["::/0"], "from_port": 443, "to_port": 443, "protocol": "tcp"}]
				}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group.open_v6", "type": "aws_security_group", "name": "open_v6",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", true, "should detect IPv6 ::/0 open ingress")
}

// --- IAC-367: Internet-facing load balancer with HTTP listener ---

func TestCrossResource_InternetLBHTTP(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_lb.public",
				"type": "aws_lb",
				"change": {"actions": ["create"], "after": {"internal": false}}
			},
			{
				"address": "aws_lb_listener.http",
				"type": "aws_lb_listener",
				"change": {"actions": ["create"], "after": {"protocol": "HTTP", "port": 80}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_lb_listener.http", "type": "aws_lb_listener", "name": "http",
					 "expressions": {"load_balancer_arn": {"references": ["aws_lb.public.arn", "aws_lb.public"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-367", true, "expected IAC-367 for internet LB + HTTP")
	assertMetadata(t, fs, "IAC-367", "load_balancer", "aws_lb.public")
	assertMetadata(t, fs, "IAC-367", "listener", "aws_lb_listener.http")
}

func TestCrossResource_InternetLBHTTP_InternalLB(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_lb.internal",
				"type": "aws_lb",
				"change": {"actions": ["create"], "after": {"internal": true}}
			},
			{
				"address": "aws_lb_listener.http",
				"type": "aws_lb_listener",
				"change": {"actions": ["create"], "after": {"protocol": "HTTP", "port": 80}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_lb_listener.http", "type": "aws_lb_listener", "name": "http",
					 "expressions": {"load_balancer_arn": {"references": ["aws_lb.internal.arn"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-367", false, "should not fire for internal LB")
}

func TestCrossResource_InternetLBHTTP_HTTPS(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_lb.public",
				"type": "aws_lb",
				"change": {"actions": ["create"], "after": {"internal": false}}
			},
			{
				"address": "aws_lb_listener.https",
				"type": "aws_lb_listener",
				"change": {"actions": ["create"], "after": {"protocol": "HTTPS", "port": 443}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_lb_listener.https", "type": "aws_lb_listener", "name": "https",
					 "expressions": {"load_balancer_arn": {"references": ["aws_lb.public.arn"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-367", false, "should not fire for HTTPS listener")
}

func TestCrossResource_InternetLBHTTP_ALB(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_alb.public",
				"type": "aws_alb",
				"change": {"actions": ["create"], "after": {"internal": false}}
			},
			{
				"address": "aws_alb_listener.http",
				"type": "aws_alb_listener",
				"change": {"actions": ["create"], "after": {"protocol": "HTTP", "port": 80}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_alb_listener.http", "type": "aws_alb_listener", "name": "http",
					 "expressions": {"load_balancer_arn": {"references": ["aws_alb.public.arn"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-367", true, "should detect via aws_alb/aws_alb_listener aliases")
}

// --- IAC-368: Public S3 bucket without encryption ---

func TestCrossResource_PublicS3NoEncryption(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.data",
				"type": "aws_s3_bucket",
				"change": {"actions": ["create"], "after": {"acl": "public-read"}}
			}
		],
		"configuration": {"root_module": {"resources": []}}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-368", true, "expected IAC-368 for public S3 without encryption")
	assertMetadata(t, fs, "IAC-368", "bucket", "aws_s3_bucket.data")
}

func TestCrossResource_PublicS3NoEncryption_WithEncryption(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.data",
				"type": "aws_s3_bucket",
				"change": {"actions": ["create"], "after": {"acl": "public-read"}}
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.data",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"change": {"actions": ["create"], "after": {}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_s3_bucket_server_side_encryption_configuration.data",
					 "type": "aws_s3_bucket_server_side_encryption_configuration", "name": "data",
					 "expressions": {"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-368", false, "should not fire when encryption config exists")
}

func TestCrossResource_PublicS3NoEncryption_PrivateBucket(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.private",
				"type": "aws_s3_bucket",
				"change": {"actions": ["create"], "after": {"acl": "private"}}
			}
		],
		"configuration": {"root_module": {"resources": []}}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-368", false, "should not fire for private bucket")
}

func TestCrossResource_PublicS3NoEncryption_PublicReadWrite(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.uploads",
				"type": "aws_s3_bucket",
				"change": {"actions": ["create"], "after": {"acl": "public-read-write"}}
			}
		],
		"configuration": {"root_module": {"resources": []}}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-368", true, "should detect public-read-write ACL")
}

// --- IAC-369: Unrestricted security group attached to database ---

func TestCrossResource_OpenSGOnDatabase(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_security_group.open",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 3306, "to_port": 3306, "protocol": "tcp"}]
				}}
			},
			{
				"address": "aws_db_instance.main",
				"type": "aws_db_instance",
				"change": {"actions": ["create"], "after": {"engine": "mysql"}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main",
					 "expressions": {"vpc_security_group_ids": {"references": ["aws_security_group.open.id", "aws_security_group.open"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-369", true, "expected IAC-369 for open SG on database")
	assertMetadata(t, fs, "IAC-369", "database", "aws_db_instance.main")
}

func TestCrossResource_OpenSGOnDatabase_RDSCluster(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_security_group.open",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 5432, "to_port": 5432, "protocol": "tcp"}]
				}}
			},
			{
				"address": "aws_rds_cluster.aurora",
				"type": "aws_rds_cluster",
				"change": {"actions": ["create"], "after": {"engine": "aurora-postgresql"}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_rds_cluster.aurora", "type": "aws_rds_cluster", "name": "aurora",
					 "expressions": {"vpc_security_group_ids": {"references": ["aws_security_group.open.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-369", true, "should detect via aws_rds_cluster")
}

func TestCrossResource_OpenSGOnDatabase_RestrictedSG(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{
				"address": "aws_security_group.restricted",
				"type": "aws_security_group",
				"change": {"actions": ["create"], "after": {
					"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 3306, "to_port": 3306, "protocol": "tcp"}]
				}}
			},
			{
				"address": "aws_db_instance.main",
				"type": "aws_db_instance",
				"change": {"actions": ["create"], "after": {"engine": "mysql"}}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main",
					 "expressions": {"vpc_security_group_ids": {"references": ["aws_security_group.restricted.id"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-369", false, "should not fire for restricted SG")
}

// --- Graph building ---

func TestBuildResourceGraph(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{"address": "aws_vpc.main", "type": "aws_vpc",
			 "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}}},
			{"address": "aws_subnet.public", "type": "aws_subnet",
			 "change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}},
			{"address": "aws_security_group.web", "type": "aws_security_group",
			 "change": {"actions": ["create"], "after": {}}}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group.web", "type": "aws_security_group", "name": "web",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}}
				]
			}
		}
	}`)

	g, err := BuildResourceGraph(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(g.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 2 {
		t.Errorf("expected 2 edges (subnet→vpc, sg→vpc), got %d", len(g.Edges))
	}

	errs := g.Validate()
	if len(errs) != 0 {
		t.Errorf("graph validation errors: %v", errs)
	}
}

func TestBuildResourceGraph_Empty(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [],
		"configuration": {"root_module": {"resources": []}}
	}`)

	g, err := BuildResourceGraph(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.Nodes))
	}
}

func TestBuildResourceGraph_InvalidJSON(t *testing.T) {
	_, err := BuildResourceGraph([]byte(`{invalid}`), "plan.json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- normalizeRef ---

func TestNormalizeRef(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aws_vpc.main.id", "aws_vpc.main"},
		{"aws_vpc.main.arn", "aws_vpc.main"},
		{"aws_lb.public.arn", "aws_lb.public"},
		{"aws_s3_bucket.data.id", "aws_s3_bucket.data"},
		{"aws_vpc.main", "aws_vpc.main"},
		{"aws_instance.web.private_ip", "aws_instance.web.private_ip"},
		{"data.aws_ami.latest", "data.aws_ami.latest"},
		{"module.network.aws_vpc.main.id", "module.network.aws_vpc.main"},
	}

	for _, tt := range tests {
		got := normalizeRef(tt.input)
		if got != tt.want {
			t.Errorf("normalizeRef(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- Integration: multiple patterns in one plan ---

func TestCrossResource_MultiplePatterns(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [
			{"address": "aws_vpc.main", "type": "aws_vpc",
			 "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}}},
			{"address": "aws_subnet.public", "type": "aws_subnet",
			 "change": {"actions": ["create"], "after": {"map_public_ip_on_launch": true}}},
			{"address": "aws_security_group.open", "type": "aws_security_group",
			 "change": {"actions": ["create"], "after": {
				"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 65535, "protocol": "-1"}]
			}}},
			{"address": "aws_db_instance.main", "type": "aws_db_instance",
			 "change": {"actions": ["create"], "after": {"engine": "mysql", "publicly_accessible": true, "storage_encrypted": false}}},
			{"address": "aws_s3_bucket.data", "type": "aws_s3_bucket",
			 "change": {"actions": ["create"], "after": {"acl": "public-read"}}},
			{"address": "aws_lb.public", "type": "aws_lb",
			 "change": {"actions": ["create"], "after": {"internal": false}}},
			{"address": "aws_lb_listener.http", "type": "aws_lb_listener",
			 "change": {"actions": ["create"], "after": {"protocol": "HTTP", "port": 80}}}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_security_group.open", "type": "aws_security_group", "name": "open",
					 "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
					{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main",
					 "expressions": {"vpc_security_group_ids": {"references": ["aws_security_group.open.id"]}}},
					{"address": "aws_lb_listener.http", "type": "aws_lb_listener", "name": "http",
					 "expressions": {"load_balancer_arn": {"references": ["aws_lb.public.arn"]}}}
				]
			}
		}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-366", true, "expected IAC-366: public subnet + open SG")
	assertFinding(t, fs, "IAC-367", true, "expected IAC-367: internet LB + HTTP")
	assertFinding(t, fs, "IAC-368", true, "expected IAC-368: public S3 no encryption")
	assertFinding(t, fs, "IAC-369", true, "expected IAC-369: open SG on database")

	// Also expect single-resource findings.
	assertFinding(t, fs, "IAC-036", true, "expected IAC-036: publicly accessible DB")
	assertFinding(t, fs, "IAC-037", true, "expected IAC-037: unencrypted storage")
	assertFinding(t, fs, "IAC-040", true, "expected IAC-040: public S3 ACL")
}

// --- Empty plan: no cross-resource findings ---

func TestCrossResource_EmptyPlan(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [],
		"configuration": {"root_module": {"resources": []}}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, ruleID := range []string{"IAC-366", "IAC-367", "IAC-368", "IAC-369"} {
		assertFinding(t, fs, ruleID, false, "should have no cross-resource findings for empty plan")
	}
}

// --- Planned values source (not resource_changes) ---

func TestCrossResource_FromPlannedValues(t *testing.T) {
	planJSON := []byte(`{
		"planned_values": {
			"root_module": {
				"resources": [
					{"address": "aws_s3_bucket.data", "type": "aws_s3_bucket", "name": "data",
					 "values": {"acl": "public-read-write"}}
				]
			}
		},
		"resource_changes": [],
		"configuration": {"root_module": {"resources": []}}
	}`)

	fs, err := scanTerraformPlanContent(planJSON, "plan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFinding(t, fs, "IAC-368", true, "should detect from planned_values source")
}

// --- Test helpers ---

func assertFinding(t *testing.T, fs *findings.FindingSet, ruleID string, expected bool, msg string) {
	t.Helper()
	found := false
	all := fs.Findings()
	for i := range all {
		if all[i].RuleID == ruleID {
			found = true
			break
		}
	}
	if found != expected {
		t.Errorf("%s (ruleID=%s, found=%v, expected=%v)", msg, ruleID, found, expected)
	}
}

func assertMetadata(t *testing.T, fs *findings.FindingSet, ruleID, key, value string) {
	t.Helper()
	all := fs.Findings()
	for i := range all {
		if all[i].RuleID == ruleID {
			if got := all[i].Metadata[key]; got != value {
				t.Errorf("finding %s: metadata[%q] = %q, want %q", ruleID, key, got, value)
			}
			return
		}
	}
	t.Errorf("finding %s not found for metadata check", ruleID)
}
