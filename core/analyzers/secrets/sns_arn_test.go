package secrets

import (
	"strings"
	"testing"
)

// SEC-519 claims "AWS SNS topic ARN". Until this test it matched one literal
// prefix, the commercial partition's service segment, behind a file keyword
// taken from a Terraform resource stem. So:
//
//   - the two other partitions AWS documents (China, GovCloud) were never
//     reported, even in a file holding the keyword;
//   - an ARN in application code, where "move it to configuration" is the
//     advice that applies, was never reported, because nothing in an ARN
//     contains the Terraform stem;
//   - the bare prefix in prose, an 11-digit account and an invalid topic name
//     were all reported as topic ARNs.
//
// Found by the concrete-witness research (docs/research/concrete-witnesses,
// #814) as replayed witnesses against the built binary. The grammar is the
// documented one: arn:partition:sns:region:account-id:topic-name, account-id
// twelve digits, topic name 1-256 of [A-Za-z0-9_-], ".fifo" for FIFO topics.

// snsARN assembles an ARN at test time so this file holds no literal the rule
// under test would report.
func snsARN(partition, region, account, topic string) string {
	return strings.Join([]string{"arn", partition, "sns", region, account, topic}, ":")
}

func TestSEC519_ReportsSNSTopicARNs(t *testing.T) {
	cases := []struct{ name, file, src string }{
		{"commercial partition, terraform", "sns.tf",
			"resource \"aws_sns_topic_subscription\" \"s\" {\n  topic_arn = \"" + snsARN("aws", "us-east-1", "123456789012", "ops-alerts") + "\"\n}\n"},
		{"china partition", "sns.tf",
			"resource \"aws_sns_topic_subscription\" \"s\" {\n  topic_arn = \"" + snsARN("aws-cn", "cn-north-1", "123456789012", "ops-alerts") + "\"\n}\n"},
		{"govcloud partition", "sns.tf",
			"resource \"aws_sns_topic_subscription\" \"s\" {\n  topic_arn = \"" + snsARN("aws-us-gov", "us-gov-west-1", "123456789012", "ops-alerts") + "\"\n}\n"},
		{"isolated partition (AWS SDK partition data)", "app.py",
			"TOPIC = \"" + snsARN("aws-iso-b", "us-isob-east-1", "123456789012", "alerts") + "\"\n"},
		{"application code with no terraform stem", "app.py",
			"TOPIC = \"" + snsARN("aws", "eu-west-1", "123456789012", "orders") + "\"\n"},
		{"fifo topic", "app.py",
			"TOPIC = \"" + snsARN("aws", "eu-west-1", "123456789012", "events.fifo") + "\"\n"},
		{"json, china partition", "policy.json",
			"{\"TopicArn\": \"" + snsARN("aws-cn", "cn-northwest-1", "123456789012", "billing") + "\"}\n"},
		{"end of a sentence", "README.md",
			"Alerts go to " + snsARN("aws", "us-east-1", "123456789012", "ops-alerts") + ".\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := findingFor(scanOne(t, tc.file, tc.src), "SEC-519"); !ok {
				t.Errorf("SEC-519 did not report an SNS topic ARN:\n%s", tc.src)
			}
		})
	}
}

func TestSEC519_DoesNotReportWhatIsNotATopicARN(t *testing.T) {
	cases := []struct{ name, file, src string }{
		{"the prefix in prose", "notes.md",
			"# aws_sns\nSNS topic ARNs begin with " + strings.Join([]string{"arn", "aws", "sns", ""}, ":") + " followed by region and account.\n"},
		{"11-digit account", "app.py",
			"# aws_sns\nt = \"" + snsARN("aws", "us-east-1", "12345678901", "alerts") + "\"\n"},
		{"topic name outside the grammar", "app.py",
			"# aws_sns\nt = \"" + snsARN("aws", "us-east-1", "123456789012", "bad.name") + "\"\n"},
		{"another service", "app.py",
			"# aws_sns\nq = \"" + strings.Join([]string{"arn", "aws", "sqs", "us-east-1", "123456789012", "jobs"}, ":") + "\"\n"},
		{"not an AWS partition", "app.py",
			"# aws_sns\nt = \"" + snsARN("awsx", "us-east-1", "123456789012", "alerts") + "\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if f, ok := findingFor(scanOne(t, tc.file, tc.src), "SEC-519"); ok {
				t.Errorf("SEC-519 reported something that is not an SNS topic ARN (line %d):\n%s", f.Location.StartLine, tc.src)
			}
		})
	}
}

func TestIsSNSTopicARN(t *testing.T) {
	long := strings.Repeat("t", 256)
	for in, want := range map[string]bool{
		snsARN("aws", "us-east-1", "123456789012", "a"):            true,
		snsARN("aws", "us-east-1", "123456789012", long):           true,
		snsARN("aws", "us-east-1", "123456789012", long+"t"):       false,
		snsARN("aws", "us-east-1", "123456789012", "x.fifo"):       true,
		snsARN("aws", "us-east-1", "123456789012", ".fifo"):        false,
		snsARN("aws", "us-east-1", "123456789012", "orders."):      true,
		snsARN("aws", "us-east-1", "123456789012", "a.b"):          false,
		snsARN("aws", "us-east-1", "123456789012", "Topic_Name-1"): true,
	} {
		if got := isSNSTopicARN(in); got != want {
			t.Errorf("isSNSTopicARN(%q) = %v, want %v", in, got, want)
		}
	}
}
