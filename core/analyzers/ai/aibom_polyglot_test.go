package ai

import (
	"strings"
	"testing"
)

func TestIsSourceFile(t *testing.T) {
	good := []string{"a.py", "b.ts", "c.go", "d.js", "e.tsx", "f.jsx", "g.rb", "h.java", "i.kt", "j.cs", "k.rs"}
	bad := []string{"a.txt", "b.md", "vendor/foo.go", "node_modules/foo.ts", "x.gen.go", "foo_test.go"}

	for _, p := range good {
		if !isSourceFile(p) {
			t.Errorf("%s should be a source file", p)
		}
	}
	for _, p := range bad {
		if isSourceFile(p) {
			t.Errorf("%s should NOT be a source file", p)
		}
	}
}

func TestIsLikelyAIContent_Hits(t *testing.T) {
	for _, marker := range []string{"openai", "anthropic", "langchain", "pinecone", "from_pretrained"} {
		if !isLikelyAIContent([]byte("// hello\n" + marker + "\n")) {
			t.Errorf("expected hit on marker %q", marker)
		}
	}
}

func TestIsLikelyAIContent_Miss(t *testing.T) {
	if isLikelyAIContent([]byte("just some normal Go code, no AI here\n")) {
		t.Error("expected miss")
	}
}

func TestExtractSDKInvocations_OpenAIChatPython(t *testing.T) {
	content := []byte(`from openai import OpenAI
client = OpenAI()
client.chat.completions.create(model="gpt-4o", messages=[])
`)
	refs := extractSDKInvocations("svc/llm.py", content)
	if len(refs) == 0 {
		t.Fatal("expected at least 1 SDK invocation reference")
	}
	if refs[0].Name != "gpt-4o" || refs[0].Registry != "openai" {
		t.Errorf("expected openai/gpt-4o, got %+v", refs[0])
	}
}

func TestExtractSDKInvocations_AnthropicTypeScript(t *testing.T) {
	content := []byte("import Anthropic from '@anthropic-ai/sdk';\n" +
		"const c = new Anthropic();\n" +
		"await c.messages.create({ model: 'claude-3-5-sonnet-20241022', messages: [] });\n")
	refs := extractSDKInvocations("api/llm.ts", content)
	if len(refs) == 0 {
		t.Fatal("expected anthropic invocation")
	}
	if !strings.HasPrefix(refs[0].Name, "claude-") || refs[0].Registry != "anthropic" {
		t.Errorf("expected anthropic claude model, got %+v", refs[0])
	}
}

func TestExtractSDKInvocations_CapturesLineAndAuthEnv(t *testing.T) {
	content := []byte(`import os
import openai

api_key = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=api_key)
client.chat.completions.create(model="gpt-4o", messages=[])
`)
	refs := extractSDKInvocations("svc/llm.py", content)
	if len(refs) == 0 {
		t.Fatal("expected at least 1 invocation")
	}
	r := refs[0]
	if r.Line == 0 {
		t.Errorf("expected non-zero line, got %d", r.Line)
	}
	if r.AuthEnvVar != "OPENAI_API_KEY" {
		t.Errorf("expected auth_env_var=OPENAI_API_KEY, got %q", r.AuthEnvVar)
	}
}

func TestExtractSDKInvocations_CapturesAzureEndpoint(t *testing.T) {
	content := []byte(`from openai import AzureOpenAI

client = AzureOpenAI(
    api_key=os.environ["AZURE_OPENAI_API_KEY"],
    azure_endpoint="https://my-resource.openai.azure.com/",
    api_version="2024-02-01",
)
client.chat.completions.create(model="gpt-4-deploy", messages=[])
`)
	refs := extractSDKInvocations("svc/azure.py", content)
	if len(refs) == 0 {
		t.Fatal("expected azure invocation")
	}
	if refs[0].Endpoint != "https://my-resource.openai.azure.com/" {
		t.Errorf("expected azure endpoint, got %q", refs[0].Endpoint)
	}
}

func TestDetectAuthEnvVar_NodeEnv(t *testing.T) {
	for _, src := range []string{
		"const k = process.env.ANTHROPIC_API_KEY;",
		"const k = process.env['ANTHROPIC_API_KEY'];",
	} {
		got := detectAuthEnvVar(src)
		if got != "ANTHROPIC_API_KEY" {
			t.Errorf("expected ANTHROPIC_API_KEY for %q, got %q", src, got)
		}
	}
}

func TestExtractFrameworkComponents_LangChainAndPinecone(t *testing.T) {
	content := []byte(`from langchain.agents import Tool
import pinecone

idx = pinecone.Index("production")
`)
	comps := extractFrameworkComponents("ingest/main.py", content)

	have := map[string]string{}
	for _, c := range comps {
		have[c.Name] = c.Type
	}
	if have["langchain"] != "agent_framework" {
		t.Errorf("expected langchain agent_framework, got %v", have)
	}
	if have["pinecone"] != "vector_store" {
		t.Errorf("expected pinecone vector_store, got %v", have)
	}
}

func TestExtractFrameworkComponents_DedupesByName(t *testing.T) {
	content := []byte(`from langchain.agents import Tool
from langchain.tools import StructuredTool
import langchain
`)
	comps := extractFrameworkComponents("agents/research.py", content)
	count := 0
	for _, c := range comps {
		if c.Name == "langchain" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected langchain to appear once, got %d", count)
	}
}
