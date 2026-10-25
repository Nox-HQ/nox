package threatmodel

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func finding(rule, sev, file string, line int, msg string, status findings.Status, meta map[string]string) findings.Finding {
	return findings.Finding{
		ID: rule + "-" + file, RuleID: rule, Severity: findings.Severity(sev),
		Location: findings.Location{FilePath: file, StartLine: line},
		Message:  msg, Fingerprint: rule + file + msg, Status: status, Metadata: meta,
	}
}

// fixture is a small but representative service: Express routes (one public,
// one with an ownership lead), an LLM agent holding a shell tool, an MCP
// server, Postgres and Stripe in the dependency set, a Terraform file with a
// bucket and a database, and a Kubernetes ingress.
func fixture() Input {
	return Input{
		NoxVersion: "9.9.9",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Report: report.JSONReport{
			Meta: report.Meta{
				SchemaVersion: "1.0.0", GeneratedAt: "2026-10-24T17:18:36Z",
				ToolName: "nox", ToolVersion: "1.2.3",
			},
			Routes: []report.Route{
				{Method: "POST", Path: "/login", FilePath: "src/server.js", Line: 6, Reader: "Express or Fastify"},
				{Method: "GET", Path: "/api/invoices/:id", FilePath: "src/routes/invoices.js", Line: 13, Authn: "requireAuth", Reader: "Express or Fastify"},
				{Method: "POST", Path: "/api/assistant/summarise", FilePath: "src/routes/assistant.js", Line: 27, Authn: "requireAuth", Reader: "Express or Fastify"},
			},
			Leads: []report.Lead{{
				Category: "authorization", RuleID: "AUTHZ-001", Route: "GET /api/invoices/:id",
				FilePath: "src/routes/invoices.js", Line: 14,
				Statement: "loads a record by a caller-supplied id with no visible ownership check",
				Test:      "Test it with two user accounts.",
			}},
			LeadChecks: []string{"authorization (Express routes; leads only)"},
			Findings: []findings.Finding{
				finding("TAINT-AI-001", "high", "src/routes/assistant.js", 28,
					`Untrusted input reaches prompt_injection sink "openai.chat.completions.create"`, findings.StatusNew,
					map[string]string{"cwe": "CWE-77", "vuln_class": "prompt_injection", "source_kind": "http_body"}),
				finding("AI-AGENT-001", "critical", "src/routes/assistant.js", 1,
					"Agent exposes shell_exec", findings.StatusNew,
					map[string]string{"cwe": "CWE-77"}),
				finding("TAINT-001", "high", "src/routes/assistant.js", 40,
					"Untrusted input reaches command_injection sink", findings.StatusNew,
					map[string]string{"cwe": "CWE-78", "vuln_class": "command_injection", "source_kind": "http_query"}),
				finding("IAC-149", "high", "deploy/k8s/ingress.yaml", 2,
					"Kubernetes Ingress without TLS configuration", findings.StatusNew,
					map[string]string{"cwe": "CWE-319", "structural_claim": `the kubernetes resource "web" (Ingress) was parsed`}),
				finding("IAC-040", "high", "deploy/tf/main.tf", 3,
					"S3 bucket with public ACL", findings.StatusNew, map[string]string{"cwe": "CWE-284"}),
				finding("IAC-036", "high", "deploy/tf/main.tf", 32,
					"RDS or database instance is publicly accessible", findings.StatusNew, map[string]string{"cwe": "CWE-284"}),
				finding("IAC-037", "medium", "deploy/tf/main.tf", 31,
					"RDS storage encryption disabled", findings.StatusSuppressed, map[string]string{"cwe": "CWE-311"}),
				finding("IAC-164", "low", "deploy/tf/main.tf", 36,
					"Terraform variable without validation block", findings.StatusNew, map[string]string{"cwe": "CWE-20"}),
				finding("VULN-001", "high", "package-lock.json", 1,
					"Known vulnerability GHSA-xxxx in axios@1.7.4", findings.StatusNew, map[string]string{}),
				finding("SEC-001", "high", "scripts/seed.sh", 4,
					"Hard-coded credential", findings.StatusNew, map[string]string{"cwe": "CWE-798"}),
			},
		},
		Inventory: &ai.Inventory{
			SchemaVersion: "2.1.0",
			Checks:        []string{"ai_security_rules", "tool_permissions"},
			Components: []ai.Component{
				{Name: "shell", Type: "mcp_server", Path: ".mcp.json", Details: map[string]string{"server": "shell", "command": "npx", "args": "-y mcp-server-shell"}},
			},
			ModelProvenance: []ai.ModelReference{{
				Name: "gpt-4o", Registry: "openai", Path: "src/routes/assistant.js", Line: 28, AuthEnvVar: "OPENAI_API_KEY",
			}},
			ToolMatrix: []ai.ToolPermissionSet{
				{
					Agent: "assistant.js", Path: "src/routes/assistant.js",
					Tools:        []string{"run_shell", "query_db", "send_email"},
					Descriptions: map[string]string{"query_db": "Run a SQL query"},
					Capabilities: map[string][]string{"run_shell": {"shell_exec"}, "send_email": {"email_send"}},
				},
				{Agent: "mcp_client", Server: "shell", Tools: []string{"*"}, Path: ".mcp.json"},
			},
		},
		SBOM: &SBOM{Name: "sbom.cdx.json", Format: "CycloneDX 1.5", Components: []Dependency{
			{Name: "axios", Version: "1.7.4"}, {Name: "openai", Version: "4.77.0"},
			{Name: "pg", Version: "8.13.1"}, {Name: "stripe", Version: "17.4.0"},
		}},
		Artifacts: []Artifact{
			{Name: "ai.inventory.json", Kind: "ai-inventory", SHA256: "cc"},
			{Name: "findings.json", Kind: "findings", SHA256: "aa"},
			{Name: "sbom.cdx.json", Kind: "sbom", SHA256: "bb"},
		},
	}
}

func build(t *testing.T) Model {
	t.Helper()
	return Build(fixture())
}

func elementByID(t *testing.T, m Model, id string) Element {
	t.Helper()
	for _, e := range m.Elements {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("element %q not in model; have %v", id, elementIDs(m))
	return Element{}
}

func hasElement(m Model, id string) bool {
	for _, e := range m.Elements {
		if e.ID == id {
			return true
		}
	}
	return false
}

func elementIDs(m Model) []string {
	var ids []string
	for _, e := range m.Elements {
		ids = append(ids, e.ID)
	}
	return ids
}

func flowsOn(m Model, boundary string) []Flow {
	var out []Flow
	for _, f := range m.Flows {
		if f.Boundary == boundary {
			out = append(out, f)
		}
	}
	return out
}

func hasFlow(m Model, from, to, boundary string) bool {
	for _, f := range m.Flows {
		if f.From == from && f.To == to && f.Boundary == boundary {
			return true
		}
	}
	return false
}

func cell(t *testing.T, m Model, element string, c Category) Cell {
	t.Helper()
	for _, r := range m.STRIDE {
		if r.Element != element {
			continue
		}
		for _, x := range r.Cells {
			if x.Category == c {
				return x
			}
		}
	}
	t.Fatalf("no STRIDE cell for %s / %s", element, c)
	return Cell{}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden; rerun with -update and review the diff", name)
	}
}
