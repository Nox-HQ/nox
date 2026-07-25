// Package confirm implements the static→dynamic AI-security confirmation loop.
//
// nox's static analyzers flag prompt-injection risks (AGENTFLOW-001,
// TAINT-AI-001, AI-PI-*): untrusted HTTP input reaching an LLM prompt call.
// "Reaches the model" is necessary but not sufficient — whether the model can
// actually be goal-hijacked depends on runtime construction (which message role
// the data lands in, what boundaries exist, how the model behaves). This package
// takes those static findings, fires an adversarial prompt-injection corpus at
// the *running* target the operator points nox at, and returns a verdict per
// finding: CONFIRMED (a payload demonstrably hijacked the model, with evidence
// and a determinism re-run) or UNCONFIRMED (no payload did).
//
// Two claims are kept strictly separate throughout, and in the emitted report:
//
//	static_flag = nox flagged this statically   (a pattern match)
//	verdict     = the confirm loop demonstrated it dynamically   (an exploit)
//
// This is an ACTIVE capability. It executes network probes — attack payloads —
// against a target the operator supplies. nox does not run or sandbox the app;
// the operator isolates the target. It is opt-in (a distinct command, never part
// of `nox scan`) and refuses to run without explicit authorization.
package confirm

import "github.com/nox-hq/nox/core/findings"

// Verdict values for a single finding.
const (
	// VerdictConfirmed means an adversarial payload demonstrably hijacked the
	// model AND the exploit reproduced under the determinism gate.
	VerdictConfirmed = "CONFIRMED"
	// VerdictUnconfirmed means no adversarial payload hijacked the model (or the
	// benign control tripped, so the harness refused to confirm anything).
	VerdictUnconfirmed = "UNCONFIRMED"
)

// Attempt records one (field × payload) probe and the model's response to it.
type Attempt struct {
	Field     string `json:"field"`
	Category  string `json:"category"`
	PayloadID string `json:"payload_id"`
	Payload   string `json:"payload"`
	Status    int    `json:"status"`
	Reply     string `json:"reply"`
	// Signal is the hijack signal detected in the reply, or "" if none. It is
	// only ever set by reflection-immune detection (see detect.go): the string
	// that trips it is never present in the payload we sent.
	Signal string `json:"signal,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Determinism records the re-run gate outcome for a candidate exploit. A
// CONFIRMED verdict requires the winning payload's hijack signal to recur in at
// least K of N total samples (the initial hit plus N-1 re-runs). For a
// deterministic endpoint K=N and responses are byte-identical; for a real model
// at temperature>0, K<N (k-of-n) tolerates sampling noise.
type Determinism struct {
	K             int      `json:"k"`
	N             int      `json:"n"`
	SignalHits    int      `json:"signal_hits"`
	Reproduced    bool     `json:"reproduced"`
	ByteIdentical bool     `json:"byte_identical"`
	Replies       []string `json:"replies,omitempty"`
}

// Evidence is the concrete proof backing a CONFIRMED verdict: the exact winning
// payload, the field it entered through, the model response that proves the
// hijack, and the determinism re-run outcome.
type Evidence struct {
	Field         string      `json:"field"`
	Category      string      `json:"category"`
	PayloadID     string      `json:"payload_id"`
	Payload       string      `json:"payload"`
	Signal        string      `json:"signal"`
	ModelResponse string      `json:"model_response"`
	Determinism   Determinism `json:"determinism"`
}

// FindingVerdict is the confirmation outcome for a single static AI-security
// finding. StaticFlag is always true (nox flagged it); Verdict is the dynamic
// result — the two are reported separately and must never be conflated.
type FindingVerdict struct {
	RuleID               string            `json:"rule_id"`
	Fingerprint          string            `json:"fingerprint"`
	Message              string            `json:"message"`
	Location             findings.Location `json:"location"`
	StaticFlag           bool              `json:"static_flag"`
	Function             string            `json:"function"`
	Route                string            `json:"route"`
	RequestFields        []string          `json:"request_fields"`
	Verdict              string            `json:"verdict"`
	DynamicallyConfirmed bool              `json:"dynamically_confirmed"`
	Evidence             *Evidence         `json:"evidence"`
	// ControlOK is nil until probing runs; false means the benign control
	// tripped a signal, so the environment is unsound and nothing was confirmed.
	ControlOK *bool     `json:"control_ok"`
	Attempts  []Attempt `json:"attempts"`
	Note      string    `json:"note,omitempty"`
}

// Report is the top-level confirmations.json document.
type Report struct {
	Label                    string           `json:"label"`
	Target                   string           `json:"target"`
	GeneratedAt              string           `json:"generated_at"`
	ReflectionImmuneAsserted bool             `json:"reflection_immune_asserted"`
	AIFindingsConsidered     []string         `json:"ai_findings_considered"`
	UniqueSinks              int              `json:"unique_sinks"`
	Results                  []FindingVerdict `json:"results"`
}

// AnyConfirmed reports whether at least one finding reached a CONFIRMED verdict.
func (r *Report) AnyConfirmed() bool {
	for i := range r.Results {
		if r.Results[i].Verdict == VerdictConfirmed {
			return true
		}
	}
	return false
}
