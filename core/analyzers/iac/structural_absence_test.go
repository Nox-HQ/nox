package iac

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// aliasTemplate is the case that motivated the structural path: two encrypted
// buckets, one of which inherits its encryption through a YAML anchor, and one
// genuinely unencrypted bucket.
//
// The regex form reports MirrorBucket, because the span it bounds by
// indentation contains only `Properties: *encrypted` and never the property the
// alias points at.
const aliasTemplate = `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties: &encrypted
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
  MirrorBucket:
    Type: AWS::S3::Bucket
    Properties: *encrypted
  PlainBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: plain
`

func iacFindings(t *testing.T, path, content, ruleID string) []findings.Finding {
	t.Helper()
	got, err := NewAnalyzer().ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	var out []findings.Finding
	for _, f := range got {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// The headline: a property reached through an anchor is a property that is
// there, and reporting it as missing is a false positive on a correctly
// hardened bucket.
func TestStructuralAbsenceRefutesAliasInheritedProperty(t *testing.T) {
	got := iacFindings(t, "stack.yaml", aliasTemplate, "IAC-051")
	if len(got) != 1 {
		for _, f := range got {
			t.Logf("  line %d", f.Location.StartLine)
		}
		t.Fatalf("IAC-051 fired %d times, want exactly 1 (the unencrypted bucket)", len(got))
	}
	// The finding must land on PlainBucket's declaration, not on either
	// encrypted bucket.
	if line := got[0].Location.StartLine; line != 13 {
		t.Errorf("finding at line %d, want 13 (PlainBucket)", line)
	}
}

// The claim is what makes this a migration rather than a precision fix: it is
// the first thing an IAC finding can say that a regex cannot.
func TestStructuralFindingCarriesAStaticClaim(t *testing.T) {
	a := NewAnalyzer()
	store := reasoning.New()
	a.RecordReasoningTo(store)

	got, err := a.ScanFile("stack.yaml", []byte(aliasTemplate))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	var target *findings.Finding
	for i := range got {
		if got[i].RuleID == "IAC-051" {
			target = &got[i]
		}
	}
	if target == nil {
		t.Fatal("IAC-051 did not fire")
	}

	claim := target.Metadata[rules.StructuralClaimKey]
	if claim == "" {
		t.Fatal("no structural claim on the finding")
	}
	if !strings.Contains(claim, "PlainBucket") || !strings.Contains(claim, "was parsed") {
		t.Errorf("claim does not name the resource it decided about: %q", claim)
	}

	subject := reasoning.Candidate(target.RuleID, "stack.yaml",
		target.Location.StartLine, target.Location.StartColumn)
	ledger := store.About(subject)

	var kinds []evidence.Kind
	var found bool
	for _, c := range ledger.Claims {
		kinds = append(kinds, c.Kind)
		if c.Kind == evidence.KindStatic && strings.Contains(c.Statement, "PlainBucket") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no KindStatic structural claim in the ledger; recorded kinds were %v", kinds)
	}
	// The ledger must read as deterministic, which is the property that lifts
	// this family off the heuristic floor. A KindStatic claim that did not
	// satisfy this would mean the kind was recorded but not counted.
	if !ledger.HasDeterministic() {
		t.Error("a structural claim did not make the ledger deterministic")
	}
}

// A document nox cannot read is not a document with nothing in it. Migration
// must ADD the structural path, never trade the text path away — otherwise
// every malformed template becomes an all-clear.
func TestUnparseableTemplateFallsBackToTextMatching(t *testing.T) {
	broken := strings.Replace(aliasTemplate, "Resources:", "Resources: [unclosed", 1)
	got := iacFindings(t, "stack.yaml", broken, "IAC-051")
	if len(got) == 0 {
		t.Fatal("a template that does not parse produced no findings at all")
	}
	for _, f := range got {
		if f.Metadata[rules.StructuralClaimKey] != "" {
			t.Error("a text-matched finding carries a structural claim")
		}
	}
}

// A pod is hardened only when EVERY container is. The "any" quantifier would
// call this Deployment safe on the strength of its first container — a finding
// hidden, which is the worse direction.
func TestEveryContainerMustBeHardened(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "1"
        - name: sidecar
`
	if got := iacFindings(t, "deploy.yaml", manifest, "IAC-145"); len(got) != 1 {
		t.Errorf("IAC-145 (security context) fired %d times, want 1 for the unhardened sidecar", len(got))
	}
	if got := iacFindings(t, "deploy.yaml", manifest, "IAC-137"); len(got) != 1 {
		t.Errorf("IAC-137 (resource limits) fired %d times, want 1 for the unhardened sidecar", len(got))
	}
}

// A template that parses and simply has no resource of the rule's type is
// decided with no findings — distinct from a template that could not be read.
func TestParsedTemplateWithoutTheResourceFiresNothing(t *testing.T) {
	tmpl := `Resources:
  Work:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: work
`
	if got := iacFindings(t, "stack.yaml", tmpl, "IAC-051"); len(got) != 0 {
		t.Errorf("IAC-051 fired on a template with no bucket: %+v", got)
	}
}

// Every migrated rule must keep its regex form. The descriptor is an addition,
// and a rule that dropped its anchor would silently stop matching every file
// the parser cannot read.
func TestMigratedRulesKeepTheirTextPath(t *testing.T) {
	var migrated int
	for _, r := range NewAnalyzer().Rules().Rules() {
		if len(r.AbsenceResourceTypes) == 0 {
			continue
		}
		migrated++
		if r.AbsenceAnchor == "" {
			t.Errorf("%s: structural descriptor but no absence anchor to fall back to", r.ID)
		}
		if r.AbsenceProperty == "" {
			t.Errorf("%s: structural descriptor but no absence property to fall back to", r.ID)
		}
		if len(r.AbsencePropertyPath) == 0 {
			t.Errorf("%s: resource types but no property path", r.ID)
		}
	}
	if migrated == 0 {
		t.Fatal("no rule carries a structural descriptor; the migration is not wired in")
	}
	t.Logf("%d absence rules carry a structural descriptor", migrated)
}
