package threatmodel

import "strings"

// This file holds the three small, explicit tables the model reads its
// vocabulary from. They are data, not heuristics: each row is a claim a
// reviewer can read and argue with, and tables_test.go pins that every rule ID
// named here still exists, so a renamed rule cannot silently turn a row into a
// dead one.

// depClass says what a package tells the model about the system.
type depClass int

const (
	depStore depClass = iota
	depService
	depAIProvider
)

// depRow maps a package, by name, to the system element its presence suggests.
// The match is the lower-cased SBOM component name; a trailing "/" in match
// means "this module path and anything under it" (Go module paths, scoped npm
// packages).
type depRow struct {
	match string
	class depClass
	// id is the element ID suffix shared by every package for one service.
	id   string
	name string
	// provider is the registry name an AI inventory uses for the same service,
	// so the two are not listed twice.
	provider string
}

var depTable = []depRow{
	// Data stores.
	{match: "pg", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "pg-promise", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "postgres", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "psycopg2", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "psycopg2-binary", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "psycopg", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "asyncpg", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "github.com/lib/pq", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "github.com/jackc/pgx/", class: depStore, id: "postgresql", name: "PostgreSQL"},
	{match: "mysql", class: depStore, id: "mysql", name: "MySQL"},
	{match: "mysql2", class: depStore, id: "mysql", name: "MySQL"},
	{match: "mysqlclient", class: depStore, id: "mysql", name: "MySQL"},
	{match: "pymysql", class: depStore, id: "mysql", name: "MySQL"},
	{match: "github.com/go-sql-driver/mysql", class: depStore, id: "mysql", name: "MySQL"},
	{match: "mongodb", class: depStore, id: "mongodb", name: "MongoDB"},
	{match: "mongoose", class: depStore, id: "mongodb", name: "MongoDB"},
	{match: "pymongo", class: depStore, id: "mongodb", name: "MongoDB"},
	{match: "motor", class: depStore, id: "mongodb", name: "MongoDB"},
	{match: "go.mongodb.org/mongo-driver", class: depStore, id: "mongodb", name: "MongoDB"},
	{match: "redis", class: depStore, id: "redis", name: "Redis"},
	{match: "ioredis", class: depStore, id: "redis", name: "Redis"},
	{match: "github.com/redis/go-redis/", class: depStore, id: "redis", name: "Redis"},
	{match: "github.com/go-redis/redis", class: depStore, id: "redis", name: "Redis"},
	{match: "github.com/gomodule/redigo", class: depStore, id: "redis", name: "Redis"},
	{match: "sqlite3", class: depStore, id: "sqlite", name: "SQLite"},
	{match: "better-sqlite3", class: depStore, id: "sqlite", name: "SQLite"},
	{match: "github.com/mattn/go-sqlite3", class: depStore, id: "sqlite", name: "SQLite"},
	{match: "@elastic/elasticsearch", class: depStore, id: "elasticsearch", name: "Elasticsearch"},
	{match: "elasticsearch", class: depStore, id: "elasticsearch", name: "Elasticsearch"},

	// External services.
	{match: "stripe", class: depService, id: "stripe", name: "Stripe (payments API)"},
	{match: "github.com/stripe/stripe-go/", class: depService, id: "stripe", name: "Stripe (payments API)"},
	{match: "twilio", class: depService, id: "twilio", name: "Twilio (messaging API)"},
	{match: "@sendgrid/mail", class: depService, id: "sendgrid", name: "SendGrid (email API)"},
	{match: "sendgrid", class: depService, id: "sendgrid", name: "SendGrid (email API)"},
	{match: "nodemailer", class: depService, id: "smtp", name: "Outbound email (SMTP)"},
	{match: "@slack/web-api", class: depService, id: "slack", name: "Slack API"},
	{match: "slack-sdk", class: depService, id: "slack", name: "Slack API"},
	{match: "aws-sdk", class: depService, id: "aws", name: "AWS APIs"},
	{match: "@aws-sdk/", class: depService, id: "aws", name: "AWS APIs"},
	{match: "boto3", class: depService, id: "aws", name: "AWS APIs"},
	{match: "github.com/aws/aws-sdk-go", class: depService, id: "aws", name: "AWS APIs"},
	{match: "@sentry/node", class: depService, id: "sentry", name: "Sentry (error reporting)"},
	{match: "sentry-sdk", class: depService, id: "sentry", name: "Sentry (error reporting)"},
	{match: "firebase-admin", class: depService, id: "firebase", name: "Firebase APIs"},
	{match: "kafkajs", class: depService, id: "kafka", name: "Kafka (message broker)"},
	{match: "amqplib", class: depService, id: "rabbitmq", name: "RabbitMQ (message broker)"},
	{match: "github.com/nats-io/nats.go", class: depService, id: "nats", name: "NATS (message broker)"},

	// AI providers. Listed as an external service only when the AI inventory
	// names no model from the same provider.
	{match: "openai", class: depAIProvider, id: "openai", name: "OpenAI API", provider: "openai"},
	{match: "github.com/sashabaranov/go-openai", class: depAIProvider, id: "openai", name: "OpenAI API", provider: "openai"},
	{match: "anthropic", class: depAIProvider, id: "anthropic", name: "Anthropic API", provider: "anthropic"},
	{match: "@anthropic-ai/sdk", class: depAIProvider, id: "anthropic", name: "Anthropic API", provider: "anthropic"},
	{match: "github.com/anthropics/anthropic-sdk-go", class: depAIProvider, id: "anthropic", name: "Anthropic API", provider: "anthropic"},
	{match: "@google/generative-ai", class: depAIProvider, id: "google-ai", name: "Google generative AI API", provider: "google"},
	{match: "google-generativeai", class: depAIProvider, id: "google-ai", name: "Google generative AI API", provider: "google"},
	{match: "cohere-ai", class: depAIProvider, id: "cohere", name: "Cohere API", provider: "cohere"},
	{match: "cohere", class: depAIProvider, id: "cohere", name: "Cohere API", provider: "cohere"},
	{match: "@mistralai/mistralai", class: depAIProvider, id: "mistral", name: "Mistral API", provider: "mistral"},
	{match: "mistralai", class: depAIProvider, id: "mistral", name: "Mistral API", provider: "mistral"},
}

// matchDependency returns the row a package name belongs to.
func matchDependency(name string) (depRow, bool) {
	low := strings.ToLower(name)
	for _, r := range depTable {
		if strings.HasSuffix(r.match, "/") {
			if strings.HasPrefix(low, r.match) || low == strings.TrimSuffix(r.match, "/") {
				return r, true
			}
			continue
		}
		if low == r.match || strings.HasPrefix(low, r.match+"/") {
			return r, true
		}
	}
	return depRow{}, false
}

// iacRow maps an infrastructure-as-code rule to the deployment element its
// finding proves exists. The model reads IaC through findings, because
// findings.json is where a scan records what it read there; a resource no rule
// fired on is therefore not in the model, and a limit says so.
type iacRow struct {
	kind string
	// sub distinguishes resources of one kind in the element ID and name.
	sub string
	// exposes marks a finding that says the resource is reachable from outside:
	// it becomes an exposure flow from the internet.
	exposes bool
}

var iacRules = map[string]iacRow{
	// Ingress.
	"IAC-149": {kind: KindIngress, exposes: true},
	"IAC-296": {kind: KindIngress, exposes: true},
	// Kubernetes workloads.
	"IAC-131": {kind: KindWorkload},
	"IAC-132": {kind: KindWorkload},
	"IAC-139": {kind: KindWorkload},
	"IAC-140": {kind: KindWorkload},
	"IAC-142": {kind: KindWorkload},
	"IAC-007": {kind: KindWorkload},
	"IAC-008": {kind: KindWorkload},
	"IAC-009": {kind: KindWorkload},
	"IAC-010": {kind: KindWorkload},
	"IAC-502": {kind: KindWorkload},
	// Container images.
	"IAC-122":  {kind: KindImage},
	"IAC-124":  {kind: KindImage},
	"CONT-002": {kind: KindImage},
	// Cloud data stores and network rules.
	"IAC-040": {kind: KindDataStore, sub: "bucket", exposes: true},
	"IAC-504": {kind: KindDataStore, sub: "bucket", exposes: true},
	"IAC-036": {kind: KindDataStore, sub: "database", exposes: true},
	"IAC-037": {kind: KindDataStore, sub: "database"},
	"IAC-004": {kind: KindNetworkRule, exposes: true},
}

// strideRow maps a weakness to the STRIDE categories it is evidence for. A
// weakness is evidence for every category it can enable, so command injection
// is both tampering and elevation of privilege.
type strideRow struct {
	cwes []string
	cats []Category
}

var strideByCWE = []strideRow{
	{[]string{"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-300", "CWE-306", "CWE-307", "CWE-308", "CWE-324", "CWE-384", "CWE-521", "CWE-613", "CWE-614"}, []Category{Spoofing}},
	{[]string{"CWE-798", "CWE-259", "CWE-321", "CWE-1188"}, []Category{Spoofing, InformationDisclosure}},
	{[]string{"CWE-20", "CWE-73", "CWE-74", "CWE-91", "CWE-116", "CWE-345", "CWE-346", "CWE-353", "CWE-434", "CWE-494", "CWE-502", "CWE-506", "CWE-601", "CWE-829", "CWE-915", "CWE-1321", "CWE-1357", "CWE-1427"}, []Category{Tampering}},
	{[]string{"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-134", "CWE-1336"}, []Category{Tampering, ElevationOfPrivilege}},
	{[]string{"CWE-89", "CWE-90", "CWE-643", "CWE-22", "CWE-23", "CWE-36"}, []Category{Tampering, InformationDisclosure}},
	{[]string{"CWE-79"}, []Category{Tampering, InformationDisclosure}},
	{[]string{"CWE-117", "CWE-223", "CWE-778"}, []Category{Repudiation}},
	{[]string{"CWE-200", "CWE-201", "CWE-209", "CWE-215", "CWE-311", "CWE-312", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-359", "CWE-497", "CWE-532", "CWE-538", "CWE-611", "CWE-918", "CWE-320"}, []Category{InformationDisclosure}},
	{[]string{"CWE-400", "CWE-405", "CWE-674", "CWE-770", "CWE-772", "CWE-834", "CWE-1333", "CWE-754", "CWE-755", "CWE-190", "CWE-362"}, []Category{DenialOfService}},
	{[]string{"CWE-250", "CWE-266", "CWE-268", "CWE-269", "CWE-276", "CWE-284", "CWE-285", "CWE-732", "CWE-862", "CWE-863", "CWE-639", "CWE-441"}, []Category{ElevationOfPrivilege}},
}

// strideByRule overrides the CWE mapping for a rule whose CWE is too general to
// say anything. AUTHZ-001 is object-level authorization: a caller reaching
// another caller's record is both elevation of privilege and disclosure.
var strideByRule = map[string][]Category{
	"AUTHZ-001": {ElevationOfPrivilege, InformationDisclosure},
	// A route anyone can call is spoofing in the STRIDE sense (the caller is
	// never established) and the privilege it exposes.
	"AUTHN-001": {Spoofing, ElevationOfPrivilege},
	// A webhook payload nobody authenticated can be forged by anyone who can
	// reach the URL.
	"WEBHOOK-001": {Spoofing, Tampering},
}

// supplyChainPrefixes are the rule families whose findings are about the
// dependency set rather than a place in the code. Their advisories carry no
// STRIDE category, so they are shown against the dependencies element as
// findings not mapped to a category.
var supplyChainPrefixes = []string{"VULN-", "SLOP-", "LIC-", "PROV-"}

// highRiskCapabilities are the agent tool capabilities a question is raised
// for, with the effect they reach.
type capEffect struct {
	id    string
	name  string
	label string
}

var capabilityEffects = map[string]capEffect{
	"shell_exec":       {"shell", "Host shell", "shell"},
	"file_read":        {"filesystem", "Host filesystem", "filesystem"},
	"file_write":       {"filesystem", "Host filesystem", "filesystem"},
	"http_request":     {"outbound", "Outbound network (HTTP, email, webhooks)", "outbound network"},
	"email_send":       {"outbound", "Outbound network (HTTP, email, webhooks)", "outbound network"},
	"webhook_post":     {"outbound", "Outbound network (HTTP, email, webhooks)", "outbound network"},
	"sql_exec":         {"database", "Database reached through a tool", "database"},
	"database_read":    {"database", "Database reached through a tool", "database"},
	"database_write":   {"database", "Database reached through a tool", "database"},
	"git_push":         {"source-control", "Source control", "source control"},
	"read_secret":      {"secrets", "Secret store", "secret store"},
	"cloud_iam_modify": {"cloud-iam", "Cloud IAM", "cloud IAM"},
	"payment_initiate": {"payments", "Payment initiation", "payment initiation"},
}

// taintEffects maps a taint vulnerability class to the effect the tainted value
// reaches and the words for the boundary it crosses.
type taintEffect struct {
	capID string
	name  string
	label string
}

var taintEffects = map[string]taintEffect{
	"command_injection":      {"shell", "Host shell", "shell command"},
	"code_injection":         {"interpreter", "Code interpreter", "evaluated code"},
	"ssti":                   {"interpreter", "Code interpreter", "evaluated code"},
	"unsafe_deserialization": {"interpreter", "Code interpreter", "evaluated code"},
	"sql_injection":          {"database", "Database reached through a tool", "database query"},
	"xpath_injection":        {"database", "Database reached through a tool", "database query"},
	"ldap_injection":         {"database", "Database reached through a tool", "database query"},
	"path_traversal":         {"filesystem", "Host filesystem", "file path"},
	"ssrf":                   {"outbound", "Outbound network (HTTP, email, webhooks)", "outbound request"},
	"xss":                    {"browser", "Caller's browser", "rendered page"},
	"open_redirect":          {"browser", "Caller's browser", "redirect target"},
	"xxe":                    {"parser", "XML parser", "parsed document"},
}
