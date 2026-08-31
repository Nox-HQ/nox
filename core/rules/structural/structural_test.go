package structural

import "testing"

const cfnYAML = `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
  LogBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: logs
`

const cfnJSON = `{
  "Resources": {
    "DataBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketEncryption": {"SSEAlgorithm": "AES256"}}
    },
    "LogBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}
  }
}`

func TestCloudFormationSeparatesEncryptedFromUnencrypted(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"yaml", cfnYAML},
		{"json", cfnJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := Evaluate([]byte(tc.doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
			if !v.Decided {
				t.Fatalf("verdict not decided: %s", v.Reason)
			}
			if len(v.Absent) != 1 || v.Absent[0].Name != "LogBucket" {
				t.Errorf("absent = %+v, want exactly LogBucket", v.Absent)
			}
			if len(v.Present) != 1 || v.Present[0].Name != "DataBucket" {
				t.Errorf("present = %+v, want exactly DataBucket", v.Present)
			}
		})
	}
}

// A resource declared with no Properties at all has nothing configured. If a
// nil Props node resolved every lookup to "present", every bare resource would
// silently stop being reported.
func TestResourceWithNoPropertiesIsAbsentNotPresent(t *testing.T) {
	doc := "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
	v := Evaluate([]byte(doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
	if !v.Decided {
		t.Fatalf("not decided: %s", v.Reason)
	}
	if len(v.Absent) != 1 {
		t.Fatalf("absent = %+v, want 1", v.Absent)
	}
}

// A key written with no value configures nothing. Counting it as present is how
// an empty key becomes an all-clear.
func TestNullValuedPropertyIsNotSet(t *testing.T) {
	doc := "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketEncryption:\n"
	v := Evaluate([]byte(doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
	if len(v.Absent) != 1 {
		t.Fatalf("a null-valued property counted as set: %+v", v)
	}
}

// An intrinsic function is a value the author supplied. Resolving it needs the
// deployment context, which is not in the file, so it must count as present —
// otherwise the mechanism templates use most reads as unconfigured.
func TestIntrinsicReferenceCountsAsPresent(t *testing.T) {
	doc := "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketEncryption: !Ref EncryptionConfig\n"
	v := Evaluate([]byte(doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
	if len(v.Present) != 1 {
		t.Fatalf("an intrinsic reference did not count as configured: %+v", v)
	}
}

const k8sDeployment = `
apiVersion: apps/v1
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
        - name: sidecar
`

// A pod is hardened only when EVERY container is. "any" would call this
// Deployment safe on the strength of one of its two containers.
func TestHasAllRequiresEveryContainer(t *testing.T) {
	path := "spec.template.spec.containers[].securityContext"

	anyV := Evaluate([]byte(k8sDeployment), []string{"Deployment"}, []string{path}, false)
	if len(anyV.Present) != 1 {
		t.Fatalf("any-quantifier should find the hardened container: %+v", anyV)
	}

	allV := Evaluate([]byte(k8sDeployment), []string{"Deployment"}, []string{path}, true)
	if len(allV.Absent) != 1 {
		t.Fatalf("all-quantifier must report the unhardened sidecar: %+v", allV)
	}
}

// A multi-document manifest is the normal form for Kubernetes; each document is
// its own object.
func TestMultiDocumentManifest(t *testing.T) {
	doc := k8sDeployment + "\n---\n" + `
apiVersion: v1
kind: Namespace
metadata:
  name: prod
`
	v := Evaluate([]byte(doc), []string{"Namespace"}, []string{"spec"}, false)
	if !v.Decided || len(v.Absent) != 1 || v.Absent[0].Name != "prod" {
		t.Fatalf("second document not read: %+v", v)
	}
}

// kubectl emits a List; a rule about a Deployment must still see one inside it.
func TestKubernetesListIsUnwrapped(t *testing.T) {
	doc := `
apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: inner
    spec: {}
`
	v := Evaluate([]byte(doc), []string{"Deployment"}, []string{"spec.template"}, false)
	if !v.Decided || len(v.Absent) != 1 || v.Absent[0].Name != "inner" {
		t.Fatalf("List was not unwrapped: %+v", v)
	}
}

const armTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-04-01",
      "name": "plain",
      "properties": {}
    },
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-04-01",
      "name": "secure",
      "properties": {"supportsHttpsTrafficOnly": true}
    }
  ]
}`

func TestARMTemplate(t *testing.T) {
	v := Evaluate([]byte(armTemplate), []string{"Microsoft.Storage/storageAccounts"},
		[]string{"properties.supportsHttpsTrafficOnly"}, false)
	if !v.Decided {
		t.Fatalf("not decided: %s", v.Reason)
	}
	if len(v.Absent) != 1 || v.Absent[0].Name != "plain" {
		t.Errorf("absent = %+v, want plain", v.Absent)
	}
	if len(v.Present) != 1 || v.Present[0].Name != "secure" {
		t.Errorf("present = %+v, want secure", v.Present)
	}
}

// A child resource declared inline is still a resource; a rule about it would
// otherwise never see it.
func TestARMNestedResources(t *testing.T) {
	doc := `{
  "resources": [{
    "type": "Microsoft.Storage/storageAccounts",
    "apiVersion": "2021-04-01",
    "name": "outer",
    "resources": [{
      "type": "Microsoft.Storage/storageAccounts/blobServices",
      "apiVersion": "2021-04-01",
      "name": "default",
      "properties": {}
    }]
  }]
}`
	v := Evaluate([]byte(doc), []string{"Microsoft.Storage/storageAccounts/blobServices"},
		[]string{"properties.deleteRetentionPolicy"}, false)
	if !v.Decided || len(v.Absent) != 1 {
		t.Fatalf("nested resource not enumerated: %+v", v)
	}
}

// The distinction the whole package rests on: a document that cannot be read
// must never read as a document with nothing in it.
func TestUnrecognisedAndUnparseableAreUndecided(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"not yaml", "{{{ this is not a document"},
		{"unrecognised schema", "version: '3'\nservices:\n  web:\n    image: nginx\n"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := Evaluate([]byte(tc.doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
			if v.Decided {
				t.Fatalf("decided a document it cannot read: %+v", v)
			}
			if v.Reason == "" {
				t.Error("undecided verdict carries no reason")
			}
		})
	}
}

// A parsed template that simply has no bucket is decided with no findings —
// distinct from the undecided case above.
func TestParsedTemplateWithoutTheResourceIsDecidedAndEmpty(t *testing.T) {
	doc := "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n    Properties: {}\n"
	v := Evaluate([]byte(doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
	if !v.Decided {
		t.Fatalf("a readable template was not decided: %s", v.Reason)
	}
	if len(v.Absent) != 0 || len(v.Present) != 0 {
		t.Fatalf("invented a resource: %+v", v)
	}
}

// A docker-compose file has a `services` key and no schema this package knows.
// Reading it as a manifest would let a rule decide about a resource that is not
// there.
func TestComposeFileIsNotReadAsKubernetes(t *testing.T) {
	doc := "version: '3'\nservices:\n  web:\n    image: nginx\n"
	docs, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := Resources(docs); len(got) != 0 {
		t.Fatalf("compose file yielded resources: %+v", got)
	}
}

// Anchors are how templates share a block, so a property reached through one
// must resolve. A lookup that stopped at the alias node would report a
// configured resource as unconfigured.
func TestAliasIsFollowedToItsValue(t *testing.T) {
	doc := `
defaults: &enc
  BucketEncryption:
    SSEAlgorithm: AES256
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties: *enc
`
	v := Evaluate([]byte(doc), []string{"AWS::S3::Bucket"}, []string{"Properties.BucketEncryption"}, false)
	if !v.Decided {
		t.Fatalf("not decided: %s", v.Reason)
	}
	if len(v.Present) != 1 {
		t.Fatalf("alias not followed to its value: %+v", v)
	}
}

func TestOversizeDocumentIsRefusedNotParsed(t *testing.T) {
	big := make([]byte, maxDocumentSize+1)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := Parse(big); err == nil {
		t.Fatal("oversize document was parsed")
	}
}

func TestPathSegments(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"a", []string{"a"}},
		{"a.b.c", []string{"a", "b", "c"}},
		{"a[].b", []string{"a", "[]", "b"}},
		{"a.*.b", []string{"a", "*", "b"}},
		{"a[][]", []string{"a", "[]", "[]"}},
	} {
		got := splitPath(tc.path)
		if len(got) != len(tc.want) {
			t.Errorf("%q -> %v, want %v", tc.path, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q -> %v, want %v", tc.path, got, tc.want)
				break
			}
		}
	}
}
