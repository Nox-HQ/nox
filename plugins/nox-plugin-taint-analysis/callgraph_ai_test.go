package main

import "testing"

func TestClassifyInterprocSink_AIPromptSinks(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"chat.completions.create", "TAINT-AI-001"},
		{"messages.create", "TAINT-AI-001"},
		{"CreateChatCompletion", "TAINT-AI-001"},
		{"GenerateContent", "TAINT-AI-001"},
		{"generate_content", "TAINT-AI-001"},
	}
	for _, c := range cases {
		got, _ := classifyInterprocSink(c.name)
		if got != c.want {
			t.Errorf("classifyInterprocSink(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyInterprocSink_AIEmbedSinks(t *testing.T) {
	cases := []string{
		"embeddings.create",
		"CreateEmbeddings",
		"cohere.embed",
		"client.Embed",
	}
	for _, c := range cases {
		got, _ := classifyInterprocSink(c)
		if got != "TAINT-AI-002" {
			t.Errorf("classifyInterprocSink(%q) = %q, want TAINT-AI-002", c, got)
		}
	}
}

func TestClassifyInterprocSink_OriginalRulesPreserved(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"db.Query", "TAINT-006"},
		{"sql_insert", "TAINT-006"},
		{"exec.Command", "TAINT-007"},
		{"shell_run", "TAINT-007"},
	}
	for _, c := range cases {
		got, _ := classifyInterprocSink(c.name)
		if got != c.want {
			t.Errorf("classifyInterprocSink(%q) = %q, want %q (regression on existing TAINT-006/007)", c.name, got, c.want)
		}
	}
}
