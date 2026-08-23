package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestHandleAttackPlan_NoScan(t *testing.T) {
	s := New("test", []string{t.TempDir()})
	out, err := s.handleAttackPlan(context.Background(), attackPlanInput{})
	if err != nil {
		t.Fatalf("attack_plan returned a transport error: %v", err)
	}
	if !out.IsError {
		t.Fatal("expected an isError result when no scan has run")
	}
	if !strings.Contains(textOf(out), "run the scan tool first") {
		t.Errorf("error text should point at the scan tool, got %q", textOf(out))
	}
}

// The plan tool must never imply anything was executed. An agent reading this
// output has to be able to tell a constructed attack path from a demonstrated
// exploit, and the only thing standing between those two readings is wording.
func TestHandleAttackPlan_NeverClaimsExecution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "agent.py", ""+
		"import openai\n"+
		"def personalize(request):\n"+
		"    persona = request.json['persona']\n"+
		"    return openai.chat.completions.create(\n"+
		"        model='gpt-4', messages=[{'role':'system','content':persona}])\n")

	s := New("0.1.0", nil)
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	out, err := s.handleAttackPlan(context.Background(), attackPlanInput{})
	if err != nil {
		t.Fatalf("attack_plan failed: %v", err)
	}
	var resp attackPlanOutput
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !strings.Contains(resp.Note, "Nothing was executed") {
		t.Errorf("note must state that nothing was executed, got %q", resp.Note)
	}
	// Whatever the plan contains, no hypothesis may claim to be confirmed.
	for _, h := range resp.Hypotheses {
		if h.Exploitability != "PLAUSIBLE" {
			t.Errorf("hypothesis %s is %s; a plan executes nothing, so every hypothesis must be PLAUSIBLE",
				h.ID, h.Exploitability)
		}
		if h.Rationale == "" {
			t.Errorf("hypothesis %s carries no rationale; a plan an operator cannot justify is one they should not run", h.ID)
		}
	}
	if resp.HowToExecute == "" || !strings.Contains(resp.HowToExecute, "--authorize") {
		t.Errorf("HowToExecute must show the operator the --authorize gate, got %q", resp.HowToExecute)
	}
}

// The ACTIVE half of `nox attack` must not be reachable over MCP.
//
// This is a security boundary, not a packaging preference: --authorize exists
// so a HUMAN affirms they own the target, and a model-initiated tool call
// cannot make that affirmation. nox also scans untrusted repositories, so an
// MCP-exposed attack runner would let attacker-controlled text in a README
// steer requests at a host of its choosing.
//
// The test asserts on the registration source, so adding a tool named
// attack_run later fails here and forces the decision to be made deliberately.
func TestActiveAttackToolsAreNotExposedOverMCP(t *testing.T) {
	src := readSourceFile(t, "attack.go")
	registrations := readSourceFile(t, "server.go") + src

	for _, forbidden := range []string{
		`Tool("attack_run")`,
		`Tool("attack_replay")`,
		`Tool("attack_regress")`,
		`Tool("confirm")`,
	} {
		if strings.Contains(registrations, forbidden) {
			t.Errorf("%s is registered as an MCP tool. Firing attack payloads requires a human "+
				"who has affirmed they own and isolated the target; a model-initiated call cannot. "+
				"If this is intentional, the rationale in server/attack.go must be revised first.", forbidden)
		}
	}
}

// attack_plan must be read-only: it reasons over scan artifacts and opens no
// socket. A future change that made it contact a target would have to remove
// this marker, which is exactly the moment to stop and think.
func TestAttackPlanIsRegisteredReadOnly(t *testing.T) {
	src := readSourceFile(t, "attack.go")
	idx := strings.Index(src, `Tool("attack_plan")`)
	if idx < 0 {
		t.Fatal("attack_plan is not registered")
	}
	// The builder chain runs until the Handler call.
	end := strings.Index(src[idx:], "Handler(")
	if end < 0 {
		t.Fatal("could not find the end of the attack_plan registration")
	}
	if !strings.Contains(src[idx:idx+end], "ReadOnly()") {
		t.Error("attack_plan must be registered ReadOnly() — it sends no traffic")
	}
}

// readSourceFile reads a file from this package's directory for the
// registration assertions above.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}
