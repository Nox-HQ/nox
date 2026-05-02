package ai

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestClassifyToolName_FileRead(t *testing.T) {
	tags := classifyToolName("read_file")
	if !contains(tags, CapFileRead) {
		t.Errorf("expected file_read for read_file, got %v", tags)
	}
}

func TestClassifyToolName_ShellExec(t *testing.T) {
	for _, name := range []string{"shell_exec", "runShell", "subprocess_call", "bash_run"} {
		tags := classifyToolName(name)
		if !contains(tags, CapShellExec) {
			t.Errorf("expected shell_exec for %s, got %v", name, tags)
		}
	}
}

func TestClassifyToolName_Unknown_NoTag(t *testing.T) {
	if got := classifyToolName("custom_business_op"); len(got) != 0 {
		t.Errorf("unknown tool should produce no tags, got %v", got)
	}
}

func TestExtractTools_PythonLangChain(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

def read_file(path):
    return open(path).read()

tools = [
    Tool(name="read_file", func=read_file, description="..."),
    Tool(name="http_post", func=lambda u, b: requests.post(u, json=b), description="..."),
]
`)
	got := extractTools("agents/research.py", src)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 tools, got %d: %+v", len(got), got)
	}
}

func TestScanAgentLattice_FileReadPlusHTTP_FlaggedHigh(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [
    Tool(name="read_file", func=fn1, description="..."),
    Tool(name="http_post", func=fn2, description="..."),
]
`)
	res := scanAgentLattice("agents/r.py", src)
	if !hasRule(res, "AI-AGENT-002") {
		t.Errorf("expected AI-AGENT-002 (file_read + http_request), got %+v", res)
	}
}

func TestScanAgentLattice_ShellExec_FlaggedCritical(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [Tool(name="run_shell", func=fn, description="...")]
`)
	res := scanAgentLattice("agents/dangerous.py", src)
	if !hasRule(res, "AI-AGENT-001") {
		t.Errorf("expected AI-AGENT-001 (shell_exec) finding, got %+v", res)
	}
	for _, f := range res {
		if f.RuleID == "AI-AGENT-001" && f.Severity != findings.SeverityCritical {
			t.Errorf("shell_exec must be critical, got %s", f.Severity)
		}
	}
}

func TestScanAgentLattice_GoMcpGo_FlaggedExfil(t *testing.T) {
	src := []byte(`package main

func init() {
    srv.Tool("read_file").Description("read").Handler(h1)
    srv.Tool("send_email").Description("send").Handler(h2)
}
`)
	res := scanAgentLattice("server/main.go", src)
	if !hasRule(res, "AI-AGENT-003") {
		t.Errorf("expected AI-AGENT-003 (file_read + email_send), got %+v", res)
	}
}

func TestExtractTools_CapturesDescription(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [
    Tool(name="read_file", description="Read any file from disk", func=fn1),
    Tool(name="http_post", description="POST data to a URL", func=fn2),
]
`)
	got := extractTools("agents/r.py", src)
	have := map[string]string{}
	for i := range got {
		have[got[i].name] = got[i].description
	}
	if have["read_file"] != "Read any file from disk" {
		t.Errorf("expected read_file description, got %v", have)
	}
	if have["http_post"] != "POST data to a URL" {
		t.Errorf("expected http_post description, got %v", have)
	}
}

func TestScanAgentLattice_FindingMetadataIncludesDescriptions(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [
    Tool(name="read_file", description="Read project files", func=fn1),
    Tool(name="http_post", description="Send data outbound", func=fn2),
]
`)
	res := scanAgentLattice("agents/r.py", src)
	for _, f := range res {
		if f.RuleID == "AI-AGENT-002" {
			desc := f.Metadata["agent_tool_descriptions"]
			if desc == "" {
				t.Fatal("expected agent_tool_descriptions metadata")
			}
			if !contains2(desc, "read_file") || !contains2(desc, "http_post") {
				t.Errorf("expected both tools in descriptions, got %q", desc)
			}
			return
		}
	}
	t.Fatal("AI-AGENT-002 not found")
}

func contains2(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestScanAgentLattice_NoCombo_NoFinding(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [Tool(name="read_file", func=fn, description="...")]
`)
	res := scanAgentLattice("agents/safe.py", src)
	for _, f := range res {
		t.Errorf("did not expect finding, got %s: %s", f.RuleID, f.Message)
	}
}

func TestScanAgentLattice_PaymentWithApprovalSuppressed(t *testing.T) {
	src := []byte(`from langchain.agents import Tool

tools = [
    Tool(name="stripe_charge", func=charge, description="..."),
    Tool(name="request_approval", func=ask, description="..."),
]
`)
	res := scanAgentLattice("agents/billing.py", src)
	if hasRule(res, "AI-AGENT-008") {
		t.Errorf("AI-AGENT-008 should be suppressed when human_approval tool present, got %+v", res)
	}
}

func contains(haystack []CapabilityTag, needle CapabilityTag) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func hasRule(in []findings.Finding, ruleID string) bool {
	for i := range in {
		if in[i].RuleID == ruleID {
			return true
		}
	}
	return false
}
