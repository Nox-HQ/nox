package iac

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

const s3Block = "resource \"aws_s3_bucket_public_access_block\" \"invoices\" {\n" +
	"  bucket                  = aws_s3_bucket.invoices.id\n" +
	"  block_public_acls       = false\n" +
	"  block_public_policy     = false\n" +
	"  ignore_public_acls      = false\n" +
	"  restrict_public_buckets = false\n" +
	"}\n"

func iac504(t *testing.T, path, body string) []findings.Finding {
	t.Helper()
	fs, err := NewAnalyzer().ScanFile(path, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out []findings.Finding
	for _, f := range fs {
		if f.RuleID == "IAC-504" {
			out = append(out, f)
		}
	}
	return out
}

// Four independent switches on one resource are one misconfiguration of one
// resource. Reporting them as four findings inflated the count and put "in 4
// places" in front of a person who has one block to edit.
func TestIAC504IsOneFindingPerResourceAndNamesTheFlags(t *testing.T) {
	fs := iac504(t, "main.tf", s3Block)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	for _, want := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets", "aws_s3_bucket_public_access_block.invoices"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message %q does not name %s", f.Message, want)
		}
	}
	if f.Location.StartLine != 3 || f.Location.EndLine != 6 {
		t.Errorf("location = lines %d-%d, want the flags, 3-6", f.Location.StartLine, f.Location.EndLine)
	}
	if f.Metadata["resource"] != "aws_s3_bucket_public_access_block.invoices" {
		t.Errorf("resource metadata = %q", f.Metadata["resource"])
	}
}

func TestIAC504NamesOnlyTheFlagsThatAreOff(t *testing.T) {
	body := strings.Replace(strings.Replace(s3Block, "block_public_policy     = false", "block_public_policy     = true", 1),
		"ignore_public_acls      = false", "ignore_public_acls      = true", 1)
	fs := iac504(t, "main.tf", body)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if !strings.Contains(fs[0].Message, "block_public_acls") || !strings.Contains(fs[0].Message, "restrict_public_buckets") ||
		strings.Contains(fs[0].Message, "block_public_policy") || strings.Contains(fs[0].Message, "ignore_public_acls") {
		t.Errorf("message names the wrong flags: %s", fs[0].Message)
	}
}

// Two resources are two findings, and which resource it is belongs to the
// identity of each: a fingerprint that ignores it would merge them.
func TestIAC504TwoResourcesAreTwoFindingsWithDistinctFingerprints(t *testing.T) {
	// The line-independent algorithm is the one that could merge them.
	prev := findings.GetFingerprintVersion()
	findings.SetFingerprintVersion(findings.FingerprintV2)
	t.Cleanup(func() { findings.SetFingerprintVersion(prev) })

	second := strings.ReplaceAll(s3Block, "\"invoices\"", "\"exports\"")
	fs := iac504(t, "main.tf", s3Block+"\n"+second)
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2", len(fs))
	}
	if fs[0].Fingerprint == fs[1].Fingerprint || fs[0].ID == fs[1].ID {
		t.Error("two resources share a line-independent identity")
	}
	// Moving the resource down the file, or fixing one of its switches, is not
	// a different finding: a waiver written against it must keep matching.
	moved := iac504(t, "main.tf", "# a comment\n\n\n"+s3Block)
	if len(moved) != 1 || moved[0].Fingerprint != fs[0].Fingerprint {
		t.Error("the fingerprint changed when the resource only moved")
	}
	fixedOne := iac504(t, "main.tf", strings.Replace(s3Block, "block_public_acls       = false", "block_public_acls       = true", 1))
	if len(fixedOne) != 1 || fixedOne[0].Fingerprint != fs[0].Fingerprint {
		t.Error("fixing one switch made the finding a different one")
	}
}

// A flag outside any resource (a tfvars file, a module call) is grouped by the
// block it sits in, and a file with no block at all by the file.
func TestIAC504OutsideAResourceIsGroupedByItsBlockOrFile(t *testing.T) {
	module := "module \"bucket\" {\n  source              = \"./s3\"\n  block_public_acls   = false\n  block_public_policy = false\n}\n"
	fs := iac504(t, "main.tf", module)
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "module.bucket") {
		t.Fatalf("module call: %+v", fs)
	}
	vars := "block_public_acls   = false\nignore_public_acls = false\n"
	fs = iac504(t, "prod.tfvars", vars)
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "block_public_acls") || !strings.Contains(fs[0].Message, "ignore_public_acls") {
		t.Fatalf("tfvars: %+v", fs)
	}
}

func TestIAC504FullyOnIsSilent(t *testing.T) {
	if fs := iac504(t, "main.tf", strings.ReplaceAll(s3Block, "false", "true")); len(fs) != 0 {
		t.Fatalf("a fully enabled block produced %+v", fs)
	}
}
