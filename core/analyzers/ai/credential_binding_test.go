package ai

import "testing"

func authOf(t *testing.T, path, src, model string) string {
	t.Helper()
	for _, r := range extractSDKInvocations(path, []byte(src)) {
		if r.Name == model {
			return r.AuthEnvVar
		}
	}
	t.Fatalf("no invocation of %s found in:\n%s", model, src)
	return ""
}

// The measured defect: a file that builds a payment client first and a model
// client second attributed the model to the payment secret (and truncated it).
func TestCredentialBinding_FollowsTheClientNotTheFile(t *testing.T) {
	src := `const Stripe = require('stripe');
const OpenAI = require('openai');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post('/chat', async (req, res) => {
  const r = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [],
  });
});
`
	if got := authOf(t, "src/server.js", src, "gpt-4o"); got != "OPENAI_API_KEY" {
		t.Fatalf("gpt-4o is fed by OPENAI_API_KEY, got %q", got)
	}
}

func TestCredentialBinding_TwoClientsTwoKeys(t *testing.T) {
	src := `const a = new OpenAI({ apiKey: process.env.TEAM_A_KEY });
const b = new OpenAI({ apiKey: process.env.TEAM_B_KEY });
a.chat.completions.create({ model: 'gpt-4o', messages: [] });
b.chat.completions.create({ model: 'gpt-4o-mini', messages: [] });
`
	if got := authOf(t, "x.js", src, "gpt-4o"); got != "TEAM_A_KEY" {
		t.Errorf("gpt-4o via a: got %q", got)
	}
	if got := authOf(t, "x.js", src, "gpt-4o-mini"); got != "TEAM_B_KEY" {
		t.Errorf("gpt-4o-mini via b: got %q", got)
	}
}

// Unknown is an answer; a guess is not.
func TestCredentialBinding_UnknownWhenItCannotBeBound(t *testing.T) {
	cases := map[string]string{
		"client built from a helper": `const client = makeClient(cfg);
const r = await client.chat.completions.create({ model: 'gpt-4o', messages: [] });
const k = process.env.UNRELATED_API_KEY;`,
		"SDK reads its default variable implicitly": `import os
client = OpenAI()
client.chat.completions.create(model="gpt-4o", messages=[])
other = os.environ["STRIPE_API_KEY"]`,
		"receiver never constructed in the file": `const r = await openai.chat.completions.create({ model: 'gpt-4o' });
const s = process.env.STRIPE_SECRET_KEY;`,
		"two constructions with different keys": `let c = new OpenAI({ apiKey: process.env.ONE_API_KEY });
c = new OpenAI({ apiKey: process.env.TWO_API_KEY });
c.chat.completions.create({ model: 'gpt-4o', messages: [] });`,
		"base url variable is not the credential": `const c = new OpenAI({ baseURL: process.env.PROXY_URL });
c.chat.completions.create({ model: 'gpt-4o', messages: [] });`,
	}
	for name, src := range cases {
		if got := authOf(t, "x.js", src, "gpt-4o"); got != "" {
			t.Errorf("%s: want unknown, got %q", name, got)
		}
	}
}

func TestCredentialBinding_Idioms(t *testing.T) {
	cases := []struct {
		name, path, src, model, want string
	}{
		{"python keyword argument", "a.py", `client = OpenAI(api_key=os.environ["MY_OPENAI_KEY"])
client.chat.completions.create(model="gpt-4o", messages=[])
stripe_key = os.environ["STRIPE_SECRET_KEY"]`, "gpt-4o", "MY_OPENAI_KEY"},
		{"python via one variable", "a.py", `key = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=key)
client.chat.completions.create(model="gpt-4o", messages=[])`, "gpt-4o", "OPENAI_API_KEY"},
		{"python self attribute", "a.py", `class S:
    def __init__(self):
        self.llm = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    def go(self):
        self.llm.messages.create(model="claude-3-5-sonnet-20241022", messages=[])`, "claude-3-5-sonnet-20241022", "ANTHROPIC_API_KEY"},
		{"go option", "a.go", `client := openai.NewClient(option.WithAPIKey(os.Getenv("OPENAI_API_KEY")))
resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "gpt-4o"})`, "gpt-4o", "OPENAI_API_KEY"},
		{"go positional", "a.go", `c := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
resp, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "gpt-4o"})`, "gpt-4o", "OPENAI_API_KEY"},
		{"bracket env access", "a.ts", `const c = new Anthropic({ apiKey: process.env["ANTHROPIC_API_KEY"] });
await c.messages.create({ model: 'claude-3-5-sonnet-20241022', messages: [] });`, "claude-3-5-sonnet-20241022", "ANTHROPIC_API_KEY"},
	}
	for _, c := range cases {
		if got := authOf(t, c.path, c.src, c.model); got != c.want {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}
