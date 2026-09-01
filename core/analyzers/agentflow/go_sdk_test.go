package agentflow

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanSource runs the analyzer over one file and returns its findings.
func scanSource(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p, Type: discovery.Source}})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	return fs.Findings()
}

func fired(fs []findings.Finding, rule string) int {
	n := 0
	for _, f := range fs {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

// nox is a language-agnostic scanner, and prompt-injection dataflow is its
// flagship AI feature. It covered Python and JS/TS: the LLM prompt SINK
// vocabulary held only the Python/JS SDK spellings, so an AI application in Go
// got no agentic dataflow analysis at all.
//
// Measured before the fix: a Go handler taking `r.URL.Query().Get("persona")`
// straight into a model call produced ZERO findings, while the line-for-line
// Python equivalent produced AGENTFLOW-001. The untrusted SOURCE was already
// recognised for Go by the taint catalog; only the destination had no Go name,
// so the flow ran from a known source to an unknown sink and stopped.
func TestGoSDKPromptCallsAreRecognised(t *testing.T) {
	tests := []struct {
		name string
		call string
	}{
		{"openai-go", "client.Chat.Completions.New(ctx, persona)"},
		{"anthropic-sdk-go", "client.Messages.New(ctx, persona)"},
		{"go-openai", "client.CreateChatCompletion(ctx, persona)"},
		{"google genai for Go", "model.GenerateContent(ctx, persona)"},
		{"langchaingo", "llms.GenerateFromSinglePrompt(ctx, persona)"},
		{"bedrock", "client.InvokeModel(ctx, persona)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "package p\n\nimport \"net/http\"\n\n" +
				"func h(w http.ResponseWriter, r *http.Request) {\n" +
				"\tpersona := r.URL.Query().Get(\"persona\")\n" +
				"\t_ = " + tt.call + "\n}\n"
			if got := fired(scanSource(t, "a.go", src), "AGENTFLOW-001"); got == 0 {
				t.Errorf("AGENTFLOW-001 did not fire on %s; an untrusted value reaches "+
					"a model prompt and nothing reported it", tt.name)
			}
		})
	}
}

// The shape the official Go SDKs actually use: parameters arrive as a struct
// literal, with the prompt nested in a slice inside it. Recognising the call
// name alone was not enough — the taint had to be seen inside the literal.
func TestGoStructLiteralParamsCarryTaint(t *testing.T) {
	src := "package p\n\nimport \"net/http\"\n\n" +
		"type Params struct {\n\tModel    string\n\tMessages []string\n}\n\n" +
		"func h(w http.ResponseWriter, r *http.Request) {\n" +
		"\tpersona := r.URL.Query().Get(\"persona\")\n" +
		"\t_ = CreateChatCompletion(r.Context(), Params{\n" +
		"\t\tModel:    \"gpt-4o\",\n" +
		"\t\tMessages: []string{\"You are a \" + persona + \" assistant.\"},\n" +
		"\t})\n}\n"
	if got := fired(scanSource(t, "a.go", src), "AGENTFLOW-001"); got == 0 {
		t.Error("AGENTFLOW-001 did not fire on the struct-literal parameter shape, " +
			"which is how every official Go LLM SDK is called")
	}
}

// A constant prompt is not an untrusted one. The rule needs a FLOW, and adding
// the Go call names must not turn every model invocation into a finding.
func TestGoPromptWithNoUntrustedInputIsClean(t *testing.T) {
	src := "package p\n\nimport \"context\"\n\n" +
		"func h(ctx context.Context) {\n" +
		"\t_ = CreateChatCompletion(ctx, \"You are a helpful assistant.\")\n}\n"
	if got := fired(scanSource(t, "a.go", src), "AGENTFLOW-001"); got != 0 {
		t.Errorf("AGENTFLOW-001 fired %d time(s) on a model call with no untrusted "+
			"input; the rule reports a flow, not a call", got)
	}
}

// The Python path must be untouched by the Go additions.
func TestPythonPathIsUnchanged(t *testing.T) {
	src := "from flask import request\nimport openai\n\n" +
		"client = openai.OpenAI()\n\n" +
		"def personalize():\n" +
		"    persona = request.json[\"persona\"]\n" +
		"    return client.chat.completions.create(model=\"gpt-4o\", messages=[{\"role\":\"system\",\"content\":f\"You are a {persona} assistant.\"}])\n"
	if got := fired(scanSource(t, "a.py", src), "AGENTFLOW-001"); got == 0 {
		t.Error("AGENTFLOW-001 stopped firing on Python")
	}
}
