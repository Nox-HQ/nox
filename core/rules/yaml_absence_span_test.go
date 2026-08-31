package rules

import (
	"strings"
	"testing"
)

// TestBraceEnclosingFallsBackToYAML is the regression for a measured
// false-negative class: every brace-enclosing absence rule silently missed
// CloudFormation written in YAML, because YAML has no braces to bound the
// resource block.
//
// The rules already list *.yaml and *.yml in their file patterns, so YAML was
// always in scope — only the span could not reach it. The fix makes
// brace-enclosing fall back to the indentation-bounded enclosing block.
func TestBraceEnclosingFallsBackToYAML(t *testing.T) {
	// Anchor at "AWS::S3::Bucket" inside a YAML resource with NO encryption
	// property. The enclosing span must cover the whole resource so the absence
	// of the property is real.
	yaml := "Resources:\n" +
		"  LogBucket:\n" +
		"    Type: AWS::S3::Bucket\n" +
		"    Properties:\n" +
		"      BucketName: my-logs\n"
	anchor := strings.Index(yaml, "AWS::S3::Bucket")
	span := absenceSpan([]byte(yaml), []int{anchor, anchor + len("AWS::S3::Bucket")}, "brace-enclosing")
	if span == nil {
		t.Fatal("brace-enclosing returned no span for a YAML resource; the whole " +
			"CloudFormation-in-YAML class stays unscanned")
	}
	if !strings.Contains(string(span), "BucketName") {
		t.Errorf("the enclosing span does not cover the resource's properties: %q", span)
	}
}

// TestTheEnclosingSpanCoversSiblingsNotJustChildren is the distinction a false
// positive taught.
//
// yamlBlockSpan bounds the block an anchor INTRODUCES; on a `Type:` line that is
// just the scalar, so a sibling property falls outside it and a configured
// resource looks unconfigured. The enclosing span must reach the sibling.
func TestTheEnclosingSpanCoversSiblingsNotJustChildren(t *testing.T) {
	yaml := "Resources:\n" +
		"  DataBucket:\n" +
		"    Type: AWS::S3::Bucket\n" +
		"    Properties:\n" +
		"      BucketName: my-data\n" +
		"      BucketEncryption:\n" +
		"        ServerSideEncryptionConfiguration: []\n"
	anchor := strings.Index(yaml, "AWS::S3::Bucket")
	span := string(absenceSpan([]byte(yaml), []int{anchor, anchor + len("AWS::S3::Bucket")}, "brace-enclosing"))
	if !strings.Contains(span, "BucketEncryption") {
		t.Errorf("the enclosing span of the Type anchor does not reach the sibling "+
			"BucketEncryption property, so an encrypted bucket would be reported as "+
			"missing encryption: %q", span)
	}
}

// TestJSONBraceSpanIsUnchanged. The fallback must only trigger when there is no
// brace — a JSON template must still be bounded by its braces exactly as before.
func TestJSONBraceSpanIsUnchanged(t *testing.T) {
	json := `{"Resources":{"LogBucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"x"}}}}`
	anchor := strings.Index(json, "AWS::S3::Bucket")
	span := string(absenceSpan([]byte(json), []int{anchor, anchor + len("AWS::S3::Bucket")}, "brace-enclosing"))
	if !strings.HasPrefix(strings.TrimSpace(span), "{") {
		t.Errorf("a JSON resource is no longer bounded by its braces: %q", span)
	}
	if !strings.Contains(span, "BucketName") {
		t.Errorf("the JSON brace span lost the resource properties: %q", span)
	}
}
