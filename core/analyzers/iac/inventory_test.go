package iac

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/infra"
)

const hardenedTF = `resource "aws_s3_bucket" "invoices" {
  bucket = "invoicely-invoices"
}
# the block is a separate resource, as it nearly always is
resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_security_group" "db" {
  name = "invoicely-db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
resource "aws_db_instance" "main" {
  engine              = "postgres"
  storage_encrypted   = true
  publicly_accessible = false
  password            = var.db_password
}
`

const weakTF = `resource "aws_s3_bucket" "invoices" {
  bucket = "invoicely-invoices"
  acl    = "public-read"
}
resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_security_group" "db" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "main" {
  storage_encrypted   = false
  publicly_accessible = true
}
`

func inventoryOf(t *testing.T, files map[string]string) infra.Inventory {
	t.Helper()
	var in []InventoryFile
	for p, c := range files {
		in = append(in, InventoryFile{Path: p, Content: []byte(c)})
	}
	return BuildInventory(in)
}

func find(t *testing.T, inv infra.Inventory, kind, name string) infra.Resource {
	t.Helper()
	for _, r := range inv.Resources {
		if r.Kind == kind && r.Name == name {
			return r
		}
	}
	t.Fatalf("no %s %q in the inventory: %+v", kind, name, inv.Resources)
	return infra.Resource{}
}

func wantProps(t *testing.T, r infra.Resource, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := r.Properties[k]; got != v {
			t.Errorf("%s: %s = %q, want %q", r.Display(), k, got, v)
		}
	}
}

func TestInventoryTerraformHardenedAndWeak(t *testing.T) {
	hard := inventoryOf(t, map[string]string{"deploy/tf/main.tf": hardenedTF})
	wantProps(t, find(t, hard, "aws_s3_bucket", "invoices"), map[string]string{
		"public_access_block": "all true", "acl": "private", "encryption": "aws:kms",
	})
	wantProps(t, find(t, hard, "aws_db_instance", "main"), map[string]string{
		"publicly_accessible": "false", "storage_encrypted": "true",
	})
	wantProps(t, find(t, hard, "aws_security_group", "db"), map[string]string{
		"open_to_world": "false", "ingress_cidrs": "10.0.0.0/16",
	})
	if find(t, hard, "aws_s3_bucket", "invoices").Class != infra.ClassBucket {
		t.Error("a bucket is class bucket")
	}

	weak := inventoryOf(t, map[string]string{"deploy/tf/main.tf": weakTF})
	wantProps(t, find(t, weak, "aws_s3_bucket", "invoices"), map[string]string{
		"public_access_block": "all false", "acl": "public-read", "encryption": "none",
	})
	wantProps(t, find(t, weak, "aws_db_instance", "main"), map[string]string{
		"publicly_accessible": "true", "storage_encrypted": "false",
	})
	wantProps(t, find(t, weak, "aws_security_group", "db"), map[string]string{"open_to_world": "true"})
}

// The block that protects a bucket is a different resource and routinely a
// different file; the reference between them is what binds them.
func TestInventoryTerraformBlockInAnotherFile(t *testing.T) {
	inv := inventoryOf(t, map[string]string{
		"a/bucket.tf": "resource \"aws_s3_bucket\" \"uploads\" {}\nresource \"aws_s3_bucket\" \"uploads_old\" {}\n",
		"a/block.tf": "resource \"aws_s3_bucket_public_access_block\" \"x\" {\n  bucket = aws_s3_bucket.uploads.id\n" +
			"  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = false\n}\n",
	})
	wantProps(t, find(t, inv, "aws_s3_bucket", "uploads"), map[string]string{"public_access_block": "partial (false: restrict_public_buckets)"})
	// `uploads_old` shares a prefix with `uploads`; the block is not its block.
	wantProps(t, find(t, inv, "aws_s3_bucket", "uploads_old"), map[string]string{"public_access_block": "absent"})
}

// A value nox cannot evaluate is recorded as dynamic and never compared.
func TestInventoryTerraformExpressionsAreDynamic(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"m.tf": "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = var.public\n  storage_encrypted = \"${var.enc}\"\n}\n" +
		"resource \"aws_s3_bucket\" \"b\" {\n  acl = var.acl\n}\n"})
	wantProps(t, find(t, inv, "aws_db_instance", "d"), map[string]string{"publicly_accessible": infra.Dynamic, "storage_encrypted": infra.Dynamic})
	wantProps(t, find(t, inv, "aws_s3_bucket", "b"), map[string]string{"acl": infra.Dynamic})
}

// Comments name resource kinds and attributes; a commented-out setting is not a
// setting.
func TestInventoryTerraformCommentsAreNotConfiguration(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"m.tf": "resource \"aws_db_instance\" \"d\" {\n  # publicly_accessible = true\n  /* storage_encrypted = false */\n  publicly_accessible = false // fine\n  storage_encrypted = true\n}\n" +
		"# resource \"aws_s3_bucket\" \"ghost\" {}\n"})
	wantProps(t, find(t, inv, "aws_db_instance", "d"), map[string]string{"publicly_accessible": "false", "storage_encrypted": "true"})
	for _, r := range inv.Resources {
		if r.Name == "ghost" {
			t.Error("a resource in a comment is not a resource")
		}
	}
}

func TestInventoryTerraformSecurityGroupRulesFold(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"m.tf": "resource \"aws_security_group\" \"web\" {}\n" +
		"resource \"aws_security_group_rule\" \"open\" {\n  type = \"ingress\"\n  security_group_id = aws_security_group.web.id\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n" +
		"resource \"aws_security_group_rule\" \"loose\" {\n  type = \"ingress\"\n  security_group_id = var.other\n  cidr_blocks = [\"::/0\"]\n}\n" +
		"resource \"aws_security_group_rule\" \"egress\" {\n  type = \"egress\"\n  security_group_id = var.other\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n"})
	wantProps(t, find(t, inv, "aws_security_group", "web"), map[string]string{"open_to_world": "true"})
	wantProps(t, find(t, inv, "aws_security_group_rule", "loose"), map[string]string{"open_to_world": "true"})
	for _, r := range inv.Resources {
		if r.Name == "open" || r.Name == "egress" {
			t.Errorf("%s should be folded into its group or not a resource", r.Display())
		}
	}
}

const hardenedDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: app
          image: ghcr.io/example/web:1.0.0@sha256:1a526b97cace6b4006256570efa1a29cd1fe4b96a5301f8d48e87c5139438a45
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 10001
            capabilities: {drop: [ALL]}
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef: {name: db, key: password}
            - name: LOG_LEVEL
              value: debug
`

const weakDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      securityContext:
        runAsNonRoot: false
      containers:
        - name: app
          image: ghcr.io/example/web:latest
          securityContext:
            allowPrivilegeEscalation: true
            privileged: true
            runAsUser: 0
            capabilities: {add: [SYS_ADMIN, cap_net_raw]}
          env:
            - name: DB_PASSWORD
              value: "hunter2-prod-Passw0rd"
`

func TestInventoryKubernetesWorkload(t *testing.T) {
	hard := inventoryOf(t, map[string]string{"d.yaml": hardenedDeployment})
	r := find(t, hard, "Deployment", "web")
	if r.Namespace != "prod" || r.Class != infra.ClassWorkload {
		t.Errorf("namespace/class = %q/%q", r.Namespace, r.Class)
	}
	wantProps(t, r, map[string]string{
		"privileged": "false", "host_network": "false", "host_pid": "false", "host_ipc": "false",
		"run_as_non_root": "true", "run_as_user": "10001", "allow_privilege_escalation": "false",
		"read_only_root_fs": "true", "capabilities_added": "none", "capabilities_drop_all": "true",
		"seccomp": "RuntimeDefault", "automount_sa_token": "false", "image_pin": "digest",
		"env.DB_PASSWORD": "secretKeyRef",
	})
	if _, ok := r.Properties["env.LOG_LEVEL"]; ok {
		t.Error("an environment variable that is not a credential is not recorded")
	}

	weak := inventoryOf(t, map[string]string{"d.yaml": weakDeployment})
	wantProps(t, find(t, weak, "Deployment", "web"), map[string]string{
		"privileged": "true", "host_network": "true", "host_pid": "true",
		"run_as_non_root": "false", "run_as_user": "0", "allow_privilege_escalation": "true",
		"read_only_root_fs": "false", "capabilities_added": "NET_RAW, SYS_ADMIN", "capabilities_drop_all": "false",
		"seccomp": "unset", "automount_sa_token": "true", "image_pin": "unpinned",
		"env.DB_PASSWORD": "literal",
	})
}

// A pod-level setting reaches containers that do not override it, and a
// container that overrides it wins.
func TestInventoryKubernetesPodLevelInheritance(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"d.yaml": `apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsNonRoot: true
          containers:
            - name: a
              image: x:1
            - name: b
              image: y:2
              securityContext:
                runAsNonRoot: false
`})
	wantProps(t, find(t, inv, "CronJob", "nightly"), map[string]string{"run_as_non_root": "false", "image_pin": "tag"})
}

func TestInventoryKubernetesIngress(t *testing.T) {
	good := inventoryOf(t, map[string]string{"i.yaml": `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts: [web.example.com]
      secretName: web-tls
  rules:
    - host: web.example.com
`})
	wantProps(t, find(t, good, "Ingress", "web"), map[string]string{"tls": "all hosts", "ssl_redirect": "true"})

	bad := inventoryOf(t, map[string]string{"i.yaml": `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  tls:
    - hosts: [web.example.com]
  rules:
    - host: web.example.com
    - host: admin.example.com
`})
	wantProps(t, find(t, bad, "Ingress", "web"), map[string]string{"tls": "partial", "ssl_redirect": "false"})

	none := inventoryOf(t, map[string]string{"i.yaml": "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  rules:\n    - host: a.example.com\n"})
	wantProps(t, find(t, none, "Ingress", "web"), map[string]string{"tls": "none", "ssl_redirect": "unset"})
}

func TestInventoryDockerfile(t *testing.T) {
	good := inventoryOf(t, map[string]string{"Dockerfile": "FROM node:20.17.0-alpine3.20@sha256:1a526b97cace6b4006256570efa1a29cd1fe4b96a5301f8d48e87c5139438a45\nWORKDIR /app\nUSER node\nCMD [\"node\"]\n"})
	wantProps(t, find(t, good, "Dockerfile", "Dockerfile"), map[string]string{"image_pin": "digest", "user": "node"})

	bad := inventoryOf(t, map[string]string{"svc/Dockerfile": "FROM node:latest\nENV API_TOKEN=abcdef123456789\nCMD [\"node\"]\n"})
	wantProps(t, find(t, bad, "Dockerfile", "Dockerfile"), map[string]string{"image_pin": "unpinned", "user": "root (no USER)", "env.API_TOKEN": "literal"})

	// Only the final stage ships: a root build stage does not make the image run as root.
	multi := inventoryOf(t, map[string]string{"Dockerfile": "FROM golang:1.22 AS build\nUSER root\nRUN go build\nFROM gcr.io/distroless/static:nonroot\nUSER 65532\nCOPY --from=build /out /out\n"})
	wantProps(t, find(t, multi, "Dockerfile", "Dockerfile"), map[string]string{"image_pin": "tag", "user": "65532"})

	// A final stage built on a named earlier stage inherits that stage's base and user.
	chained := inventoryOf(t, map[string]string{"Dockerfile": "FROM alpine:3.20 AS base\nUSER app\nFROM base\nCMD [\"sh\"]\n"})
	wantProps(t, find(t, chained, "Dockerfile", "Dockerfile"), map[string]string{"image_pin": "tag", "user": "app"})

	// A build ARG in FROM cannot be evaluated.
	arg := inventoryOf(t, map[string]string{"Dockerfile": "ARG BASE\nFROM ${BASE}\n"})
	wantProps(t, find(t, arg, "Dockerfile", "Dockerfile"), map[string]string{"image_pin": infra.Dynamic})
}

func TestInventoryCompose(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"docker-compose.yml": `services:
  db:
    image: postgres
    privileged: true
    network_mode: host
    user: "1000"
    cap_add: [SYS_ADMIN]
    environment:
      POSTGRES_PASSWORD: hunter2-prod-Passw0rd
      LOG: debug
  app:
    image: app:1.2
    environment:
      - API_KEY=${API_KEY}
`})
	wantProps(t, find(t, inv, "compose_service", "db"), map[string]string{
		"image_pin": "unpinned", "privileged": "true", "host_network": "true", "user": "1000",
		"capabilities_added": "SYS_ADMIN", "env.POSTGRES_PASSWORD": "literal",
	})
	wantProps(t, find(t, inv, "compose_service", "app"), map[string]string{
		"image_pin": "tag", "user": "root (no user)", "env.API_KEY": "variable",
	})
}

func TestInventoryCloudFormation(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"t.yaml": `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Uploads:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: false
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: !Ref Enc
`})
	wantProps(t, find(t, inv, "AWS::S3::Bucket", "Uploads"), map[string]string{
		"public_access_block": "partial (false: block_public_policy)", "acl": "PublicRead", "encryption": "none",
	})
	wantProps(t, find(t, inv, "AWS::RDS::DBInstance", "Db"), map[string]string{
		"publicly_accessible": "true", "storage_encrypted": infra.Dynamic,
	})
}

// Two runs over the same tree give the same bytes, whatever order the files
// were handed in.
func TestInventoryIsDeterministic(t *testing.T) {
	files := map[string]string{"a.tf": hardenedTF, "b.yaml": hardenedDeployment, "Dockerfile": "FROM node:20\n"}
	first := inventoryOf(t, files)
	for i := 0; i < 20; i++ {
		if got := inventoryOf(t, files); !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}

// Identity carries no line number: shifting a resource down changes its
// location and nothing else.
func TestInventoryIdentityIgnoresLines(t *testing.T) {
	a := inventoryOf(t, map[string]string{"m.tf": hardenedTF})
	b := inventoryOf(t, map[string]string{"m.tf": "# a comment\n# another\n\n" + hardenedTF})
	if len(a.Resources) != len(b.Resources) {
		t.Fatal("moving a block changed the resource count")
	}
	for i := range a.Resources {
		if a.Resources[i].ID() != b.Resources[i].ID() || a.Resources[i].Line == b.Resources[i].Line {
			t.Errorf("%s: id or line unexpectedly equal after a move", a.Resources[i].ID())
		}
	}
	if len(infra.Compare(&a, &b)) != 0 {
		t.Error("a pure move reported a change")
	}
}

func TestInventoryDuplicateIdentitiesAreSeparated(t *testing.T) {
	inv := inventoryOf(t, map[string]string{"d.yaml": hardenedDeployment + "---\n" + hardenedDeployment})
	n := 0
	for _, r := range inv.Resources {
		if strings.HasPrefix(r.Name, "web") {
			n++
		}
	}
	if n != 2 || len(inv.Index()) != 2 {
		t.Errorf("two identical documents must stay two resources, got %d / %d", n, len(inv.Index()))
	}
}

// The scan's own side product is the same inventory.
func TestAnalyzerExposesTheInventory(t *testing.T) {
	a := NewAnalyzer()
	if !a.Inventory().Empty() {
		t.Error("a fresh analyzer has read nothing")
	}
}
