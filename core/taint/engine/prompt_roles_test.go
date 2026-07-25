package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// sinkRoleFor returns the SinkRole of the first TAINT-AI-001 (prompt-injection)
// flow in flows, and whether such a flow was found. It is how the role-aware tests
// assert both that the finding fired and which role it landed in.
func sinkRoleFor(flows []taint.Flow) (string, bool) {
	for i := range flows {
		if flows[i].Sink.RuleID == "TAINT-AI-001" {
			return flows[i].SinkRole, true
		}
	}
	return "", false
}

// TestPromptRoleAwareTaint is the end-to-end discrimination proof for the
// role-aware prompt-injection rule (TAINT-AI-001), driven through the real
// extractor + structural engine. It encodes all three directions the design
// requires: system-role FIRES, user-role-behind-a-static-system does NOT, and
// ambiguous/dynamic construction FIRES (conservative).
func TestPromptRoleAwareTaint(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantFire bool
		wantRole string // asserted only when wantFire is true
	}{
		{
			// The false positive this whole change removes: untrusted input reaches
			// the model ONLY in the user role, behind a static system message.
			name: "user role behind static system does not fire",
			src: `def chat():
    user_q = request.args.get("q")
    client.chat.completions.create(messages=[{"role": "system", "content": "Answer concisely."}, {"role": "user", "content": user_q}])
`,
			wantFire: false,
		},
		{
			// The true positive that must survive: untrusted persona in the SYSTEM
			// role inverts the trust boundary — a real prompt injection.
			name: "system role fires",
			src: `def personalize():
    persona = request.args.get("persona")
    client.chat.completions.create(messages=[{"role": "system", "content": persona}, {"role": "user", "content": "hi"}])
`,
			wantFire: true,
			wantRole: taint.PromptRoleSystem,
		},
		{
			// f-string interpolation into the system role still lands in system.
			name: "system role via f-string fires",
			src: `def personalize():
    persona = request.args.get("persona")
    client.chat.completions.create(messages=[{"role": "system", "content": f"You are a {persona} bot."}, {"role": "user", "content": "hi"}])
`,
			wantFire: true,
			wantRole: taint.PromptRoleSystem,
		},
		{
			// Conservative: the message array is built dynamically (a bare variable),
			// so the landing role is undetermined — keep the finding.
			name: "dynamic message construction fires conservatively",
			src: `def chat():
    q = request.args.get("q")
    msgs = [{"role": "system", "content": q}]
    client.chat.completions.create(messages=msgs)
`,
			wantFire: true,
			wantRole: taint.PromptRoleUnknown,
		},
		{
			// A lone user message with NO system boundary: there is no static
			// data/instruction separation, so the value is kept (conservative). This
			// mirrors the existing agentflow expectation and prevents an over-broad
			// suppression that would hide real injections.
			name: "user role without static system fires",
			src: `def chat():
    q = request.args.get("q")
    client.chat.completions.create(messages=[{"role": "user", "content": q}])
`,
			wantFire: true,
			wantRole: taint.PromptRoleUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := analyze(t, lexctx.LangPython, tt.src)
			role, fired := sinkRoleFor(flows)
			if fired != tt.wantFire {
				t.Fatalf("TAINT-AI-001 fired = %v, want %v (flows: %v)", fired, tt.wantFire, ruleIDs(flows))
			}
			if tt.wantFire && role != tt.wantRole {
				t.Errorf("sink_role = %q, want %q", role, tt.wantRole)
			}
		})
	}
}
