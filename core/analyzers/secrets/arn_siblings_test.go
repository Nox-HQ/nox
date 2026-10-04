package secrets

import (
	"strings"
	"testing"
)

// The eleven ARN rules beside SEC-519 were built the way SEC-519 was before
// #817: a literal prefix in the commercial partition only, behind a file
// keyword taken from a Terraform resource stem that no ARN contains. So ARNs
// in the China and GovCloud partitions were never reported, ARNs in
// application code were never reported, and a bare prefix in prose was. Each
// rule now matches the ARN grammar its service documents, in every partition,
// and a validator judges the resource segment.
//
// ARNs are assembled at test time, so this file holds no literal the rules
// under test would report.

func arnOf(partition, service, region, account, resource string) string {
	return strings.Join([]string{"arn", partition, service, region, account, resource}, ":")
}

type arnRuleCase struct {
	id, service string
	regional    bool   // region and account segments present
	resource    string // a valid resource segment
	invalid     string // a resource segment the service's grammar rejects
	// oldKeyword is the Terraform stem the rule used to require in the file.
	// The negative cases carry it, so they would have fired before the fix
	// and do not pass merely because the old pre-filter never ran.
	oldKeyword string
}

var arnRuleCases = []arnRuleCase{
	{"SEC-414", "rds", true, "cluster:orders-db", "cluster:", "aws_rds"},
	{"SEC-514", "rds", true, "db:orders-primary", "db:1orders", "aws_rds"},
	{"SEC-465", "iam", false, "user/ci/deploy", "role/*", "aws_iam"},
	{"SEC-516", "iam", false, "role/service-role/deploy", "role/" + strings.Repeat("r", 65), "aws_iam_role"},
	{"SEC-466", "secretsmanager", true, "secret:prod/db-AbCdEf", "secret:" + strings.Repeat("s", 520), "aws_secret"},
	{"SEC-511", "ecs", true, "task-definition/web:3", "task-definition/web:latest", "aws_ecs"},
	{"SEC-512", "lambda", true, "function:worker:$LATEST", "function:bad.name", "aws_lambda"},
	{"SEC-513", "s3", false, "my-assets-bucket/*", "My_Bucket", "aws_s3"},
	{"SEC-515", "ec2", true, "instance/i-0123456789abcdef0", "instance/i-0abc", "aws_ec2"},
	{"SEC-517", "dynamodb", true, "table/orders/index/by-day", "table/ab", "aws_dynamodb"},
	{"SEC-518", "sqs", true, "jobs.fifo", "bad.name", "aws_sqs"},
}

var arnPartitions = []struct{ partition, region string }{
	{"aws", "us-east-1"},
	{"aws-cn", "cn-north-1"},
	{"aws-us-gov", "us-gov-west-1"},
}

func (c arnRuleCase) arn(partition, region, account, resource string) string {
	switch {
	case c.service == "s3":
		return arnOf(partition, c.service, "", "", resource)
	case !c.regional:
		return arnOf(partition, c.service, "", account, resource)
	}
	return arnOf(partition, c.service, region, account, resource)
}

func TestARNRules_ReportARNsInEveryPartition(t *testing.T) {
	for _, c := range arnRuleCases {
		for _, p := range arnPartitions {
			src := "RESOURCE = \"" + c.arn(p.partition, p.region, "123456789012", c.resource) + "\"\n"
			t.Run(c.id+"/"+p.partition, func(t *testing.T) {
				if _, ok := findingFor(scanOne(t, "app.py", src), c.id); !ok {
					t.Errorf("%s did not report its ARN in application code:\n%s", c.id, src)
				}
			})
		}
	}
}

func TestARNRules_DoNotReportWhatIsNotTheirARN(t *testing.T) {
	for _, c := range arnRuleCases {
		prefix := strings.Join([]string{"arn", "aws", c.service, ""}, ":")
		head := "# " + c.oldKeyword + "\n"
		cases := map[string]string{
			"bare prefix in prose": head + "ARNs for this service begin with " + prefix + " and then the region.\n",
			"invalid resource":     head + "R = \"" + c.arn("aws", "us-east-1", "123456789012", c.invalid) + "\"\n",
			"template region":      head + "R = \"" + c.arn("aws", "${var.region}", "123456789012", c.resource) + "\"\n",
		}
		if c.service != "s3" {
			cases["11-digit account"] = head + "R = \"" + c.arn("aws", "us-east-1", "12345678901", c.resource) + "\"\n"
		}
		if !c.regional || c.service == "s3" {
			delete(cases, "template region") // no region segment to template
		}
		for name, src := range cases {
			t.Run(c.id+"/"+name, func(t *testing.T) {
				if f, ok := findingFor(scanOne(t, "app.py", src), c.id); ok {
					t.Errorf("%s reported something that is not its ARN (line %d):\n%s", c.id, f.Location.StartLine, src)
				}
			})
		}
	}
}

// AWS managed policies carry "aws" where the account goes. They are IAM ARNs,
// which is SEC-465's claim, and were reported before this change.
func TestSEC465_ReportsAWSManagedPolicyARN(t *testing.T) {
	src := "POLICY = \"" + arnOf("aws", "iam", "", "aws", "policy/ReadOnlyAccess") + "\"\n"
	if _, ok := findingFor(scanOne(t, "app.py", src), "SEC-465"); !ok {
		t.Errorf("SEC-465 did not report an AWS managed policy ARN:\n%s", src)
	}
}

// A sentence may end right after an ARN. The punctuation is not part of it.
func TestARNRules_TrailingPunctuation(t *testing.T) {
	for _, end := range []string{".", ","} {
		src := "Jobs land in " + arnOf("aws", "sqs", "eu-west-1", "123456789012", "jobs") + end + " then a worker runs.\n"
		if _, ok := findingFor(scanOne(t, "README.md", src), "SEC-518"); !ok {
			t.Errorf("SEC-518 missed an ARN followed by %q:\n%s", end, src)
		}
	}
}

// An IAM path segment and the name are 1+ characters (IAM identifiers):
// "role/" with nothing after it, or "role/a//b", names no role. allBytes
// rejects the empty string, which is what holds this; the test pins it.
func TestIAMRoleARN_RejectsEmptySegments(t *testing.T) {
	const prefix = "arn:aws:iam::123456789012:"
	for _, res := range []string{"role/", "role/svc//deploy", "role//deploy"} {
		if isIAMRoleARN(prefix + res) {
			t.Errorf("accepted %q", prefix+res)
		}
	}
	if !isIAMRoleARN(prefix + "role/svc/deploy") {
		t.Errorf("rejected a valid role ARN with a path")
	}
}
