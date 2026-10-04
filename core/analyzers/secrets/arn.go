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
const snsTopicARNPattern = `\b` + arnPartition + `:sns:` + arnRegion + `:` + arnAccount + `:[A-Za-z0-9_.-]+`

// The pieces every ARN rule shares. arnPartition is the partition set
// described above; arnRegion and arnAccount are the region and 12-digit
// account segments of a regional, account-scoped ARN. A literal "aws" where
// the partition goes, a region that is a template expression, or an account
// that is not twelve digits is not an ARN of the kind these rules claim.
const (
	arnPartition = `arn:aws(?:-cn|-us-gov|-iso(?:-[bef])?|-eusc)?`
	arnRegion    = `[a-z][a-z0-9-]*[0-9]`
	arnAccount   = `[0-9]{12}`
	// arnResource is a greedy run over every character a resource segment of
	// the services below can hold. Each rule's validator then parses it: RE2
	// cannot say "and then no further name character", so a bounded class
	// would match the valid-looking head of an invalid name.
	arnResource = `[A-Za-z0-9_.:/+=,@$*-]+`
)

// regionalARN is the candidate pattern for service svc's ARNs whose resource
// segment begins with resPrefix: arn:partition:svc:region:account:resPrefix...
func regionalARN(svc, resPrefix string) string {
	return `\b` + arnPartition + `:` + svc + `:` + arnRegion + `:` + arnAccount + `:` + resPrefix + arnResource
}

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

// arnResourceAfter returns the resource segment of an ARN candidate: what
// follows the first occurrence of marker, with sentence punctuation (a
// trailing full stop or comma) removed.
func arnResourceAfter(arn, marker string) (string, bool) {
	i := strings.Index(arn, marker)
	if i < 0 {
		return "", false
	}
	return strings.TrimRight(arn[i+len(marker):], ".,"), true
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return s != ""
}

func isAlnumByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// nameBytes accepts the alphanumerics plus extra.
func nameBytes(extra string) func(byte) bool {
	return func(c byte) bool { return isAlnumByte(c) || strings.IndexByte(extra, c) >= 0 }
}

// isRDSARN: arn:partition:rds:region:account:resource-type:name (Amazon RDS
// User Guide, "Amazon Resource Names (ARNs) in Amazon RDS"). The resource
// type is a lowercase word (db, cluster, snapshot, pg, subgrp, ...) and the
// name an identifier of letters, digits and hyphens (snapshot names also
// carry dots and colons in automated forms, so those are allowed).
func isRDSARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":rds:")
	if !ok {
		return false
	}
	// region:account:type:name
	parts := strings.SplitN(res, ":", 4)
	if len(parts) != 4 {
		return false
	}
	typ, name := parts[2], parts[3]
	return allBytes(typ, func(c byte) bool { return c >= 'a' && c <= 'z' || c == '-' }) &&
		len(name) <= 255 && allBytes(name, nameBytes("-.:"))
}

// isRDSInstanceARN: an RDS ARN whose resource type is db, with a DB instance
// identifier: 1-63 letters, digits or hyphens, starting with a letter, not
// ending with a hyphen, no two consecutive hyphens (CreateDBInstance,
// DBInstanceIdentifier constraints).
func isRDSInstanceARN(arn string) bool {
	if !isRDSARN(arn) {
		return false
	}
	res, _ := arnResourceAfter(arn, ":rds:")
	parts := strings.SplitN(res, ":", 4)
	if parts[2] != "db" {
		return false
	}
	id := parts[3]
	if len(id) == 0 || len(id) > 63 || !(id[0] >= 'a' && id[0] <= 'z' || id[0] >= 'A' && id[0] <= 'Z') {
		return false
	}
	return !strings.HasSuffix(id, "-") && !strings.Contains(id, "--") && allBytes(id, nameBytes("-"))
}

// isIAMARN: arn:partition:iam::account:resource (IAM User Guide, "IAM
// identifiers", ARNs). IAM is global: the region segment is empty. The
// account is twelve digits, or "aws" for AWS managed policies. The resource
// is "root" or type/path/name, names over [\w+=,.@-] and paths over "/".
func isIAMARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":iam::")
	if !ok {
		return false
	}
	acct, rest, ok := strings.Cut(res, ":")
	if !ok || (acct != "aws" && !(len(acct) == 12 && allBytes(acct, func(c byte) bool { return c >= '0' && c <= '9' }))) {
		return false
	}
	if rest == "root" {
		return true
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || !allBytes(typ, func(c byte) bool { return c >= 'a' && c <= 'z' || c == '-' }) {
		return false
	}
	return iamPathName(path, 128)
}

// iamPathName accepts an optional path ("a/b/") and a name of 1-max
// characters over [\w+=,.@-]; neither may be empty between slashes.
func iamPathName(path string, max int) bool {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		limit := 512
		if i == len(segs)-1 {
			limit = max
		}
		if len(seg) > limit || !allBytes(seg, nameBytes("_+=,.@-")) {
			return false
		}
	}
	return true
}

// isIAMRoleARN: arn:partition:iam::account:role/[path/]name, role names
// 1-64 characters (CreateRole, RoleName).
func isIAMRoleARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":role/")
	return ok && isIAMARN(arn) && iamPathName(res, 64)
}

// isSecretsManagerARN: arn:partition:secretsmanager:region:account:secret:
// name, where name is up to 512 of [A-Za-z0-9/_+=.@-]; issued ARNs append a
// hyphen and six random characters, and partial ARNs without them are valid
// in IAM policies, so both are accepted (Secrets Manager User Guide, "Secret
// ARN" and CreateSecret, Name).
func isSecretsManagerARN(arn string) bool {
	name, ok := arnResourceAfter(arn, ":secret:")
	return ok && len(name) <= 512+7 && allBytes(name, nameBytes("/_+=.@-"))
}

// isECSTaskDefinitionARN: arn:partition:ecs:region:account:task-definition/
// family[:revision], family 1-255 of letters, digits, hyphens and
// underscores, revision a positive integer (RegisterTaskDefinition, family).
func isECSTaskDefinitionARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":task-definition/")
	if !ok {
		return false
	}
	family, rev, hasRev := strings.Cut(res, ":")
	if len(family) > 255 || !allBytes(family, nameBytes("-_")) {
		return false
	}
	return !hasRev || allBytes(rev, func(c byte) bool { return c >= '0' && c <= '9' })
}

// isLambdaFunctionARN: arn:partition:lambda:region:account:function:name
// [:qualifier], name 1-64 of [A-Za-z0-9_-], qualifier $LATEST, a version
// number or an alias of [A-Za-z0-9_-] (Lambda API, FunctionName and
// Qualifier patterns).
func isLambdaFunctionARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":function:")
	if !ok {
		return false
	}
	name, q, hasQ := strings.Cut(res, ":")
	if len(name) > 64 || !allBytes(name, nameBytes("_-")) {
		return false
	}
	return !hasQ || q == "$LATEST" || (len(q) <= 128 && allBytes(q, nameBytes("_-")))
}

// isS3BucketARN: arn:partition:s3:::bucket[/key], the region and account
// segments empty (S3 User Guide, "Amazon S3 resources" ARN formats). The
// bucket name follows the general-purpose naming rules: 3-63 of lowercase
// letters, digits, dots and hyphens, beginning and ending with a letter or
// digit, no two adjacent dots. The object key, often a policy wildcard, is
// not judged.
func isS3BucketARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":s3:::")
	if !ok {
		return false
	}
	bucket, _, _ := strings.Cut(res, "/")
	if len(bucket) < 3 || len(bucket) > 63 || strings.Contains(bucket, "..") {
		return false
	}
	lowerDigit := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	return lowerDigit(bucket[0]) && lowerDigit(bucket[len(bucket)-1]) &&
		allBytes(bucket, func(c byte) bool { return lowerDigit(c) || c == '.' || c == '-' })
}

// isEC2InstanceARN: arn:partition:ec2:region:account:instance/i-<id>, the
// id 8 or 17 lowercase hex digits (EC2 User Guide, "Resource IDs").
func isEC2InstanceARN(arn string) bool {
	id, ok := arnResourceAfter(arn, ":instance/i-")
	return ok && (len(id) == 8 || len(id) == 17) &&
		allBytes(id, func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' })
}

// isDynamoDBTableARN: arn:partition:dynamodb:region:account:table/name, name
// 3-255 of [A-Za-z0-9_.-] (DynamoDB naming rules), optionally followed by a
// sub-resource path (/index/..., /stream/..., /backup/..., /export/...).
func isDynamoDBTableARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":table/")
	if !ok {
		return false
	}
	name, _, _ := strings.Cut(res, "/")
	return len(name) >= 3 && len(name) <= 255 && allBytes(name, nameBytes("_.-"))
}

// isSQSQueueARN: arn:partition:sqs:region:account:queue-name, the name 1-80
// of [A-Za-z0-9_-], FIFO queue names ending in ".fifo" within the 80
// (CreateQueue, QueueName).
func isSQSQueueARN(arn string) bool {
	res, ok := arnResourceAfter(arn, ":sqs:")
	if !ok {
		return false
	}
	parts := strings.SplitN(res, ":", 3)
	if len(parts) != 3 {
		return false
	}
	name := parts[2]
	if len(name) > 80 {
		return false
	}
	return allBytes(strings.TrimSuffix(name, ".fifo"), nameBytes("_-"))
}
