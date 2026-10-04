package secrets

import "strings"

// snsTopicARNPattern is SEC-519's candidate: an ARN whose service segment is
// sns, in any AWS partition, with a region, a 12-digit account and a topic.
//
// Partitions: aws, aws-cn and aws-us-gov are the ones the IAM ARN reference
// documents. The isolated partitions (aws-iso, -iso-b, -iso-e, -iso-f) and
// aws-eusc are not in that page but are in AWS's own SDK partition data
// (aws-sdk-go-v2 internal/endpoints/awsrulesfn/partitions.json). They are
// included: an ARN in one is an SNS topic ARN all the same, and the partition
// token is specific enough that including it costs nothing.
//
// The topic segment is matched greedily over [A-Za-z0-9_.-] and judged by
// isSNSTopicARN, because RE2 cannot say "and then no further name character":
// a bounded class would match the valid-looking head of an invalid name.
const snsTopicARNPattern = `\barn:aws(?:-cn|-us-gov|-iso(?:-[bef])?|-eusc)?:sns:[a-z][a-z0-9-]*[0-9]:[0-9]{12}:[A-Za-z0-9_.-]+`

// isSNSTopicARN reports whether a SEC-519 candidate's topic segment is a
// topic name: 1-256 of [A-Za-z0-9_-], with ".fifo" for FIFO topics
// (CreateTopic API reference). A trailing full stop is a sentence ending, not
// part of the ARN.
func isSNSTopicARN(arn string) bool {
	i := strings.LastIndexByte(arn, ':')
	if i < 0 {
		return false
	}
	name := strings.TrimRight(arn[i+1:], ".")
	name = strings.TrimSuffix(name, ".fifo")
	if name == "" || len(name) > 256 {
		return false
	}
	for j := 0; j < len(name); j++ {
		if !isTopicNameByte(name[j]) {
			return false
		}
	}
	return true
}

func isTopicNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '_' || c == '-'
}
