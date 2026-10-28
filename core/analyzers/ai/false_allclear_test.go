package ai

import (
	"strings"
	"testing"
)

// A filesystem MCP server rooted at "/" is the widest grant there is, and the
// rule named for broad filesystem scope matched /Users/, /home/ and ~ only, so
// the widest grant scanned clean while a narrower one was a CRITICAL. The same
// file also launched two servers from the package registry with no version and
// one with an "allow everything" switch in its env; none of it was reported.
// Each case is a real configuration shape, paired with its safe form.

func mcpRuleCount(t *testing.T, path, body, rule string) int {
	t.Helper()
	got, err := NewAnalyzer().ScanFile(path, []byte(body))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	n := 0
	for _, f := range got {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

func TestFalseAllClear_MCPConfigRules(t *testing.T) {
	server := func(command string, args string, env string) string {
		cfg := `{"mcpServers":{"srv":{"command":"` + command + `","args":` + args
		if env != "" {
			cfg += `,"env":` + env
		}
		return cfg + `}}}`
	}
	cases := []struct {
		name string
		rule string
		body string
		want int
	}{
		// ---- MCP-002: a filesystem server rooted somewhere vast ----------
		{"filesystem server rooted at /", "MCP-002",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem@2025.1.14","/"]`, ""), 1},
		{"filesystem server rooted at a Windows drive", "MCP-002",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem@2025.1.14","C:\\"]`, ""), 1},
		{"filesystem server rooted at /etc", "MCP-002",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem@2025.1.14","/etc"]`, ""), 1},
		{"filesystem server rooted at /var/", "MCP-002",
			server("mcp-fs", `["/var/"]`, ""), 1},
		{"filesystem server rooted at /root", "MCP-002",
			server("mcp-fs", `["--root","/root"]`, ""), 1},
		{"filesystem server rooted at ${HOME}", "MCP-002",
			server("mcp-fs", `["${HOME}"]`, ""), 1},
		{"filesystem server rooted at the project", "MCP-002",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem@2025.1.14","./docs"]`, ""), 0},
		{"filesystem server rooted at an application directory", "MCP-002",
			server("mcp-fs", `["/srv/invoicely/exports"]`, ""), 0},
		{"a lone slash that is not a path argument", "MCP-002",
			`{"mcpServers":{"srv":{"command":"mcp-x","args":["--sep","a/b"],"cwd":"/"}}}`, 0},
		{"a URL argument", "MCP-002",
			server("mcp-x", `["--endpoint","https://api.example.com/"]`, ""), 0},

		// ---- MCP-003: an env switch that grants everything ---------------
		{"ALLOW_ALL=1 in env", "MCP-003",
			server("mcp-shell-server", `["--stdio"]`, `{"ALLOW_ALL":"1"}`), 1},
		{"dangerous-sounding env set true", "MCP-003",
			server("mcp-x", `[]`, `{"DANGEROUSLY_SKIP_PERMISSIONS":"true"}`), 1},
		{"ALLOW_ALL explicitly off", "MCP-003",
			server("mcp-shell-server", `["--stdio"]`, `{"ALLOW_ALL":"0"}`), 0},
		{"an unrelated env var", "MCP-003",
			server("mcp-x", `[]`, `{"LOG_LEVEL":"debug","ALLOWED_HOSTS":"api.example.com"}`), 0},
		{"a server merely named shell, with no evidence in command or args", "MCP-003",
			`{"mcpServers":{"shell":{"command":"mcp-x","args":["--stdio"]}}}`, 0},

		// ---- MCP-025: launched from the registry with no pinned version --
		{"npx package with no version", "MCP-025",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem","./docs"]`, ""), 1},
		{"unscoped npx package with no version", "MCP-025",
			server("npx", `["-y","mcp-server-shell"]`, `{"LOG_LEVEL":"info"}`), 1},
		{"npx package on the latest tag", "MCP-025",
			server("npx", `["-y","mcp-server-shell@latest"]`, ""), 1},
		{"npx package on a semver range", "MCP-025",
			server("npx", `["-y","mcp-server-shell@^1.2.0"]`, ""), 1},
		{"uvx package with no version", "MCP-025",
			server("uvx", `["mcp-server-git"]`, ""), 1},
		{"args declared before command", "MCP-025",
			`{"mcpServers":{"srv":{"args":["-y","mcp-server-shell"],"command":"npx"}}}`, 1},
		{"npx package pinned to an exact version", "MCP-025",
			server("npx", `["-y","@modelcontextprotocol/server-filesystem@2025.1.14","./docs"]`, ""), 0},
		{"unscoped npx package pinned to an exact version", "MCP-025",
			server("npx", `["-y","mcp-server-shell@1.2.3"]`, ""), 0},
		{"uvx package pinned with ==", "MCP-025",
			server("uvx", `["mcp-server-git==0.6.2"]`, ""), 0},
		{"uvx package pinned with @", "MCP-025",
			server("uvx", `["mcp-server-git@0.6.2"]`, ""), 0},
		{"a locally installed binary is not fetched at launch", "MCP-025",
			server("node", `["./servers/invoices.js"]`, ""), 0},
		{"an npx flag that takes a package, pinned", "MCP-025",
			server("npx", `["-y","--package","mcp-server-shell@1.2.3","mcp-server-shell"]`, ""), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mcpRuleCount(t, ".mcp.json", tc.body, tc.rule); got != tc.want {
				t.Fatalf("%s fired %d times, want %d\n%s", tc.rule, got, tc.want, tc.body)
			}
		})
	}
}

// The measured configuration, verbatim: it has to produce all three.
func TestFalseAllClear_TheMeasuredMCPConfig(t *testing.T) {
	cfg := `{
  "mcpServers": {
    "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"] },
    "shell": { "command": "npx", "args": ["-y", "mcp-server-shell"], "env": { "ALLOW_ALL": "1" } }
  }
}`
	for rule, want := range map[string]int{"MCP-002": 1, "MCP-003": 1, "MCP-025": 2} {
		if got := mcpRuleCount(t, ".mcp.json", cfg, rule); got != want {
			t.Errorf("%s fired %d times, want %d", rule, got, want)
		}
	}
}

// ---- 5. a tool whose parameter is model-supplied SQL ------------------------

const queryDBTool = `const tools = [
  { type: "function", function: { name: "query_db", description: "Run a SQL query against the invoices database",
      parameters: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } } },
];
const handlers = { query_db: async ({ sql }) => (await db.query(sql)).rows };
`

const getInvoiceTool = `const tools = [
  { type: "function", function: { name: "get_invoice", description: "Fetch one invoice by its id",
      parameters: { type: "object", properties: { invoice_id: { type: "string" } }, required: ["invoice_id"] } } },
];
const handlers = { get_invoice: async ({ invoice_id }) => (await db.query("SELECT * FROM invoices WHERE id = $1", [invoice_id])).rows };
`

func toolTags(t *testing.T, path, src string) map[string][]CapabilityTag {
	t.Helper()
	out := map[string][]CapabilityTag{}
	for _, tool := range extractTools(path, []byte(src)) {
		out[tool.name] = tool.tags
	}
	return out
}

func TestFalseAllClear_SQLParameterToolGetsACapability(t *testing.T) {
	cases := []struct {
		name, path, src, tool string
		want                  bool
	}{
		{"openai function tool with an sql parameter", "assistant.js", queryDBTool, "query_db", true},
		{"a tool that takes an id and runs a fixed statement", "assistant.js", getInvoiceTool, "get_invoice", false},
		{"python langchain tool taking a raw sql string", "tools.py", `from langchain.agents import tool

@tool("invoice_lookup")
def invoice_lookup(sql: str) -> str:
    """Look things up in the invoices database."""
    return str(cursor.execute(sql).fetchall())
`, "invoice_lookup", true},
		{"a generic query parameter on a tool described as SQL", "assistant.js", `const tools = [
  { type: "function", function: { name: "ledger", description: "Run a read-only SQL statement on the ledger",
      parameters: { type: "object", properties: { query: { type: "string" } } } } },
];
`, "ledger", true},
		{"a query parameter on a search tool is a search string", "assistant.js", `const tools = [
  { type: "function", function: { name: "search_docs", description: "Search the help centre",
      parameters: { type: "object", properties: { query: { type: "string" } } } } },
];
`, "search_docs", false},
		{"a tool whose name says sql but takes no sql", "assistant.js", `const tools = [
  { type: "function", function: { name: "explain_sql_error", description: "Explain a database error code",
      parameters: { type: "object", properties: { code: { type: "string" } } } } },
];
`, "explain_sql_error", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tags := toolTags(t, tc.path, tc.src)[tc.tool]
			if got := contains(tags, CapSQLExec); got != tc.want {
				t.Fatalf("tool %s tags %v; sql_exec = %v, want %v", tc.tool, tags, got, tc.want)
			}
		})
	}
}

// The measured assistant registers three tools and then, after them, a handler
// table that calls db.query(sql). Reading the handler as the last tool's
// schema gave send_email a SQL capability.
func TestFalseAllClear_ASQLCallAfterTheRegistrationsIsNotAParameter(t *testing.T) {
	src := `const tools = [
  { type: "function", function: { name: "run_shell", description: "Run a shell command on the server",
      parameters: { type: "object", properties: { cmd: { type: "string" } }, required: ["cmd"] } } },
  { type: "function", function: { name: "query_db", description: "Run a SQL query against the invoices database",
      parameters: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } } },
  { type: "function", function: { name: "send_email", description: "Send an email to any address",
      parameters: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } }, required: ["to", "body"] } } },
];
const handlers = {
  run_shell: ({ cmd }) => execSync(cmd).toString(),
  query_db: async ({ sql }) => (await db.query(sql)).rows,
  send_email: ({ to, body }) => mailer.sendMail({ to, text: body }),
};
`
	tags := toolTags(t, "assistant.js", src)
	for tool, want := range map[string]bool{"run_shell": false, "query_db": true, "send_email": false} {
		if got := contains(tags[tool], CapSQLExec); got != want {
			t.Errorf("%s: sql_exec = %v, want %v (tags %v)", tool, got, want, tags[tool])
		}
	}
}

func TestFalseAllClear_SQLToolAppearsInTheToolMatrix(t *testing.T) {
	sets := extractToolPermissions("src/routes/assistant.js", []byte(queryDBTool), nil)
	if len(sets) == 0 {
		t.Fatal("no tool permission set for the file")
	}
	var caps []string
	for _, s := range sets {
		caps = append(caps, s.Capabilities["query_db"]...)
	}
	if !strings.Contains(strings.Join(caps, ","), string(CapSQLExec)) {
		t.Fatalf("tool_permission_matrix has no %s capability for query_db: %v", CapSQLExec, caps)
	}
}

// Model-supplied SQL is an escalation primitive on its own: the statement is
// the model's output, so a prompt injection chooses it, and what it can do is
// whatever the connection's role can do. Fixed-statement tools do not trip it.
func TestFalseAllClear_SQLToolIsFlaggedByTheLattice(t *testing.T) {
	var ids []string
	for _, f := range scanAgentLattice("assistant.js", []byte(queryDBTool)) {
		ids = append(ids, f.RuleID)
	}
	if !strings.Contains(strings.Join(ids, ","), "AI-AGENT-009") {
		t.Fatalf("lattice did not flag a tool that executes model-supplied SQL: %v", ids)
	}
	if got := scanAgentLattice("assistant.js", []byte(getInvoiceTool)); len(got) != 0 {
		t.Fatalf("a fixed-statement tool produced lattice findings: %+v", got)
	}
}
