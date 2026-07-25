package agentflow

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scan writes one source file and returns the rule IDs the analyzer emits, in
// deterministic finding order. The filename's extension drives the language.
func scan(t *testing.T, name, content string) []findings.Finding {
	t.Helper()
	root := t.TempDir()
	abs := filepath.Join(root, name)
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	art := discovery.Artifact{Path: name, AbsPath: abs, Type: discovery.Source}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// ruleIDs projects a finding slice to its rule IDs.
func ruleIDs(fs []findings.Finding) []string {
	out := make([]string, 0, len(fs))
	for i := range fs {
		out = append(out, fs[i].RuleID)
	}
	return out
}

// has reports whether ruleID appears among the findings.
func has(fs []findings.Finding, ruleID string) bool {
	for i := range fs {
		if fs[i].RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestAgentflow(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		src     string
		want    string // rule expected to fire ("" = expect nothing)
		notWant string // rule that must NOT fire
	}{
		// -------- AGENTFLOW-001: untrusted input -> LLM prompt --------
		{
			name: "python request arg into chat completion messages",
			file: "app.py",
			src: `def handler():
    q = request.args.get("q")
    openai.chat.completions.create(messages=[{"role": "user", "content": q}])
`,
			want: ruleUntrustedToPrompt,
		},
		{
			name: "python env var into anthropic messages create",
			file: "agent.py",
			src: `def run():
    ctx = os.getenv("CTX")
    client.messages.create(model="claude", messages=[{"role": "user", "content": ctx}])
`,
			want: ruleUntrustedToPrompt,
		},
		{
			name: "python fetched external content into gemini prompt (indirect injection)",
			file: "rag.py",
			src: `def ask():
    doc = urllib.request.urlopen(url)
    model.generate_content(doc)
`,
			want: ruleUntrustedToPrompt,
		},
		{
			name: "js req body into chat completion",
			file: "route.ts",
			src: `function handler(req) {
  const q = req.body;
  openai.chat.completions.create({ messages: [{ role: "user", content: q }] });
}`,
			want: ruleUntrustedToPrompt,
		},
		{
			name: "python untrusted propagated through reassignment",
			file: "prop.py",
			src: `def h():
    raw = request.form.get("m")
    prompt = raw
    openai.chat.completions.create(messages=[{"role": "user", "content": prompt}])
`,
			want: ruleUntrustedToPrompt,
		},

		// -------- AGENTFLOW-002: LLM output -> dangerous sink --------
		{
			name: "python llm output into os.system",
			file: "exec.py",
			src: `def act():
    r = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])
    os.system(r.choices[0].message.content)
`,
			want: ruleOutputToSink,
		},
		{
			name: "python llm output into cursor execute",
			file: "sql.py",
			src: `def act():
    r = openai.chat.completions.create(messages=[])
    cursor.execute(r.choices[0].message.content)
`,
			want: ruleOutputToSink,
		},
		{
			name: "python llm output into eval",
			file: "eval.py",
			src: `def act():
    out = model.generate_content("do math")
    eval(out.text)
`,
			want: ruleOutputToSink,
		},
		{
			name: "js llm output into child_process exec",
			file: "shell.ts",
			src: `async function act() {
  const r = await openai.chat.completions.create({ messages: [] });
  child_process.exec(r.choices[0].message.content);
}`,
			want: ruleOutputToSink,
		},
		{
			name: "python llm output propagated then executed",
			file: "prop2.py",
			src: `def act():
    r = client.chat.completions.create(messages=[])
    cmd = r.choices[0].message.content
    os.system(cmd)
`,
			want: ruleOutputToSink,
		},

		// -------- Role-aware AGENTFLOW-001 (P3) --------
		// Reaching an LLM is necessary but not sufficient: WHERE the untrusted value
		// lands is the differentiator. These three cases encode the design contract.
		{
			// TRUE POSITIVE kept: untrusted value in the SYSTEM role inverts the
			// trust boundary (a real prompt injection).
			name: "tainted value in system role fires",
			file: "sys.py",
			src: `def personalize():
    persona = request.args.get("persona")
    openai.chat.completions.create(messages=[{"role": "system", "content": persona}, {"role": "user", "content": "hi"}])
`,
			want: ruleUntrustedToPrompt,
		},
		{
			// TRUE POSITIVE kept: f-string interpolation into the system role.
			name: "tainted value in system role via f-string fires",
			file: "sysf.py",
			src: `def personalize():
    persona = request.args.get("persona")
    openai.chat.completions.create(messages=[{"role": "system", "content": f"You are a {persona} bot."}, {"role": "user", "content": "hi"}])
`,
			want: ruleUntrustedToPrompt,
		},
		{
			// FALSE POSITIVE removed: untrusted value confined to the user role,
			// behind a STATIC system message — the recommended data-boundary pattern
			// (this is exactly examples/ai-app/safe.py).
			name: "tainted value in user role behind static system does not fire",
			file: "usr.py",
			src: `def chat():
    user_q = request.args.get("q")
    openai.chat.completions.create(messages=[{"role": "system", "content": "Answer concisely."}, {"role": "user", "content": user_q}])
`,
			want:    "",
			notWant: ruleUntrustedToPrompt,
		},
		{
			// CONSERVATIVE: the message array is built dynamically (a bare variable),
			// so the landing role is undetermined — keep the finding.
			name: "dynamic message construction still fires",
			file: "dyn.py",
			src: `def chat():
    q = request.args.get("q")
    msgs = [{"role": "system", "content": q}]
    openai.chat.completions.create(messages=msgs)
`,
			want: ruleUntrustedToPrompt,
		},

		// -------- No-fire cases --------
		{
			name: "hardcoded constant prompt does not fire",
			file: "const.py",
			src: `def h():
    prompt = "summarize the following report"
    openai.chat.completions.create(messages=[{"role": "user", "content": prompt}])
`,
			want:    "",
			notWant: ruleUntrustedToPrompt,
		},
		{
			name: "llm output only printed does not fire 002",
			file: "print.py",
			src: `def h():
    r = client.chat.completions.create(messages=[])
    print(r.choices[0].message.content)
`,
			want:    "",
			notWant: ruleOutputToSink,
		},
		{
			name: "llm output only returned does not fire 002",
			file: "ret.py",
			src: `def h():
    r = client.chat.completions.create(messages=[])
    return r.choices[0].message.content
`,
			want:    "",
			notWant: ruleOutputToSink,
		},
		{
			name: "sanitized input before prompt does not fire 001",
			file: "san.py",
			src: `def h():
    q = request.args.get("q")
    safe = shlex.quote(q)
    openai.chat.completions.create(messages=[{"role": "user", "content": safe}])
`,
			want:    "",
			notWant: ruleUntrustedToPrompt,
		},
		{
			name: "unrelated untrusted-to-classic-sink does not fire agentflow",
			file: "classic.py",
			src: `def h():
    q = request.args.get("q")
    os.system(q)
`,
			want:    "",
			notWant: ruleUntrustedToPrompt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := scan(t, tt.file, tt.src)
			if tt.want != "" && !has(fs, tt.want) {
				t.Errorf("expected %s to fire, got %v", tt.want, ruleIDs(fs))
			}
			if tt.notWant != "" && has(fs, tt.notWant) {
				t.Errorf("expected %s NOT to fire, got %v", tt.notWant, ruleIDs(fs))
			}
			if tt.want == "" && tt.notWant == "" && len(fs) != 0 {
				t.Errorf("expected no findings, got %v", ruleIDs(fs))
			}
		})
	}
}

// TestDeterminism verifies repeated scans of the same source yield byte-identical
// finding order and content — the offline/deterministic guarantee.
func TestDeterminism(t *testing.T) {
	src := `def handler():
    q = request.args.get("q")
    r = openai.chat.completions.create(messages=[{"role": "user", "content": q}])
    os.system(r.choices[0].message.content)
`
	first := ruleIDs(scan(t, "det.py", src))
	for i := 0; i < 5; i++ {
		got := ruleIDs(scan(t, "det.py", src))
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("nondeterministic output: %v vs %v", first, got)
		}
	}
	// This file exercises both flows; both rules must be present.
	if !has(scan(t, "det.py", src), ruleUntrustedToPrompt) {
		t.Errorf("expected %s in combined flow", ruleUntrustedToPrompt)
	}
	if !has(scan(t, "det.py", src), ruleOutputToSink) {
		t.Errorf("expected %s in combined flow", ruleOutputToSink)
	}
}

// TestRulesDeclared verifies Rules() declares exactly the two IDs the analyzer
// emits, with the ASI tags the fleet convention expects.
func TestRulesDeclared(t *testing.T) {
	rs := NewAnalyzer().Rules()
	byID := map[string]bool{}
	for _, r := range rs.Rules() {
		byID[r.ID] = true
	}
	for _, id := range []string{ruleUntrustedToPrompt, ruleOutputToSink} {
		if !byID[id] {
			t.Errorf("Rules() missing %s", id)
		}
	}
	// Tag convention check: 001 -> asi01, 002 -> asi02.
	for _, r := range rs.Rules() {
		wantTag := ""
		switch r.ID {
		case ruleUntrustedToPrompt:
			wantTag = "owasp-asi01"
		case ruleOutputToSink:
			wantTag = "owasp-asi02"
		}
		found := false
		for _, tag := range r.Tags {
			if tag == wantTag {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing tag %s (tags: %v)", r.ID, wantTag, r.Tags)
		}
	}
}

// TestMetadataCarriesTriage verifies findings carry the source/sink triage
// metadata callers rely on for explanation.
func TestMetadataCarriesTriage(t *testing.T) {
	fs := scan(t, "meta.py", `def h():
    q = request.args.get("q")
    openai.chat.completions.create(messages=[{"role": "user", "content": q}])
`)
	var f *findings.Finding
	for i := range fs {
		if fs[i].RuleID == ruleUntrustedToPrompt {
			f = &fs[i]
		}
	}
	if f == nil {
		t.Fatalf("no %s finding", ruleUntrustedToPrompt)
	}
	if f.Metadata["source_var"] != "q" {
		t.Errorf("source_var = %q, want q", f.Metadata["source_var"])
	}
	if f.Metadata["owasp_asi"] != "ASI01" {
		t.Errorf("owasp_asi = %q, want ASI01", f.Metadata["owasp_asi"])
	}
}
