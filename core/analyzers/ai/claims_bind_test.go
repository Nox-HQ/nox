package ai

import "testing"

// AI-036 claims an application uses a deprecated model. It matched any
// `gpt-3.5` string, so an SDK that merely LISTS the model reported it: 330
// findings across five of the seven benchmark repositories, drawn from
// openai-python's accepted-model Literals and crewAI's context-window table.
// Those say a model exists; they do not select it. The claim is made where a
// model is chosen — an argument, a config key, an environment variable.
func TestAI036_ReportsASelectedModelNotAMention(t *testing.T) {
	a := NewAnalyzer()
	selects := map[string]string{
		"app.py":       `resp = client.chat.completions.create(model="gpt-3.5-turbo", messages=m)`,
		"chain.py":     `llm = ChatOpenAI(model_name="gpt-3.5-turbo")`,
		"config.yaml":  "llm:\n  model: gpt-3.5-turbo\n",
		"request.json": `{"model": "gpt-3.5-turbo", "messages": []}`,
		"app.env":      "OPENAI_MODEL=gpt-3.5-turbo\n",
		"client.ts":    `const r = await openai.chat.completions.create({ model: 'gpt-3.5-turbo' })`,
	}
	for name, src := range selects {
		if r, _ := a.ScanFile(name, []byte(src)); findingWithRule(r, "AI-036") == nil {
			t.Errorf("AI-036 must report the model selected in %s: %q", name, src)
		}
	}
	mentions := map[string]string{
		// openai-python src/openai/resources/beta/assistants.py
		"assistants.py": "        model: Union[str, Literal[\n            \"gpt-4\",\n            \"gpt-3.5-turbo\",\n        ]],",
		// crewAI lib/crewai/src/crewai/llms/providers/azure/completion.py
		"completion.py": `    "gpt-3.5-turbo": 16385,`,
		// crewAI lib/crewai/src/crewai/llm.py
		"llm.py":   `    for prefix in ["gpt-", "gpt-3.5-", "o1", "azure-"]:`,
		"notes.py": `# gpt-3.5-turbo is deprecated; use a current model`,
	}
	for name, src := range mentions {
		if r, _ := a.ScanFile(name, []byte(src)); findingWithRule(r, "AI-036") != nil {
			t.Errorf("AI-036 reported a mention, not a selection, in %s: %q", name, src)
		}
	}
}

// AI-050 claims an LLM client runs with retries disabled. It matched
// `retry = False` and `retries = None` anywhere, so internal control flow
// reported it — crewAI's `should_retry = False`, openai-python's own
// `self._retry = None` in its streaming parser. The claim is a client or
// request configured with max_retries 0.
func TestAI050_ReportsAClientWithRetriesOffNotControlFlow(t *testing.T) {
	a := NewAnalyzer()
	disabled := map[string]string{
		"client.py":   `client = OpenAI(max_retries=0)`,
		"client.ts":   `const client = new Anthropic({ maxRetries: 0 })`,
		"config.yaml": "openai:\n  max_retries: 0\n",
	}
	for name, src := range disabled {
		if r, _ := a.ScanFile(name, []byte(src)); findingWithRule(r, "AI-050") == nil {
			t.Errorf("AI-050 must report a client with retries off in %s: %q", name, src)
		}
	}
	flow := map[string]string{
		"tool_usage.py": `        should_retry = False`,
		"_streaming.py": `        self._retry = None`,
		"loop.py":       `    retries = 0  # attempt counter`,
		"client2.py":    `client = OpenAI(max_retries=3)`,
		"client3.py":    `client = OpenAI(max_retries=10)`,
	}
	for name, src := range flow {
		if r, _ := a.ScanFile(name, []byte(src)); findingWithRule(r, "AI-050") != nil {
			t.Errorf("AI-050 reported control flow or an enabled retry in %s: %q", name, src)
		}
	}
}
