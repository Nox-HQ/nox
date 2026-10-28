package ai

import "testing"

func endpointOf(t *testing.T, path, src, model string) string {
	t.Helper()
	for _, r := range extractSDKInvocations(path, []byte(src)) {
		if r.Name == model {
			return r.Endpoint
		}
	}
	t.Fatalf("no invocation of %s found in:\n%s", model, src)
	return ""
}

// The measured shape: one file, a default client and a gateway client. The
// first base URL in the file used to be recorded against both models.
func TestEndpointBinding_FollowsTheClientNotTheFile(t *testing.T) {
	src := `const gateway = new OpenAI({ apiKey: process.env.GW_KEY, baseURL: "https://llm.internal.example/v1" });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
gateway.chat.completions.create({ model: 'gpt-4o', messages: [] });
openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [] });
`
	if got := endpointOf(t, "x.js", src, "gpt-4o"); got != "https://llm.internal.example/v1" {
		t.Errorf("gpt-4o goes through the gateway, got %q", got)
	}
	if got := endpointOf(t, "x.js", src, "gpt-4o-mini"); got != "" {
		t.Errorf("gpt-4o-mini uses the provider default, got %q", got)
	}
}

func TestEndpointBinding_PythonAndGoForms(t *testing.T) {
	py := `client = OpenAI(api_key=os.environ["K"], base_url="https://gw.example/v1")
client.chat.completions.create(model="gpt-4o", messages=[])
`
	if got := endpointOf(t, "a.py", py, "gpt-4o"); got != "https://gw.example/v1" {
		t.Errorf("python base_url: got %q", got)
	}
	br := `client = boto3.client("bedrock-runtime", region_name="eu-central-1")
client.invoke_model(modelId="anthropic.claude-3", body=b)
`
	if got := endpointOf(t, "b.py", br, "anthropic.claude-3"); got != "eu-central-1" {
		t.Errorf("bedrock region: got %q", got)
	}
	mod := `openai.base_url = "https://mod.example/v1"
openai.chat.completions.create(model="gpt-4o", messages=[])
`
	if got := endpointOf(t, "c.py", mod, "gpt-4o"); got != "https://mod.example/v1" {
		t.Errorf("module-level base_url: got %q", got)
	}
}

// Unknown is an answer; a guess is not.
func TestEndpointBinding_UnknownWhenItCannotBeBound(t *testing.T) {
	cases := map[string]string{
		"client from a helper": `const client = makeClient(cfg);
client.chat.completions.create({ model: 'gpt-4o', messages: [] });
const x = { baseURL: "https://other.example/v1" };`,
		"endpoint not a literal": `const c = new OpenAI({ baseURL: process.env.GW_URL });
c.chat.completions.create({ model: 'gpt-4o', messages: [] });`,
		"two constructions that differ": `c = OpenAI(base_url="https://a.example/v1")
c = OpenAI(base_url="https://b.example/v1")
c.chat.completions.create(model="gpt-4o", messages=[])`,
		"receiver never constructed": `const r = await openai.chat.completions.create({ model: 'gpt-4o' });
const y = { baseURL: "https://other.example/v1" };`,
	}
	for name, src := range cases {
		if got := endpointOf(t, "x.js", src, "gpt-4o"); got != "" {
			t.Errorf("%s: endpoint must be unknown, got %q", name, got)
		}
	}
}
