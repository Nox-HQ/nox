package attack

import (
	"strings"
	"testing"
)

// allPayloadSpecs flattens every scenario's specs (attacks and controls) for a
// seed. Unlike PayloadCorpus it keeps the payloadSpec so tests can reason about
// id, category, and control, not just the text.
func allPayloadSpecs(cs *CanarySet) []payloadSpec {
	var out []payloadSpec
	for _, s := range Scenarios() {
		out = append(out, scenarioPayloads(s.ID, cs)...)
	}
	return out
}

// expandedPayloadIDs are the strategy variants added on top of the original
// per-scenario seed set. The test asserts each is present and reflection-immune,
// so a regression that drops or corrupts one is caught explicitly rather than
// hiding inside the whole-corpus aggregate.
var expandedPayloadIDs = []string{
	// PI-DIRECT: encoding, leetspeak, role-marker hierarchy, multi-turn, encoded leak.
	"pi-direct-b64-transform",
	"pi-direct-leet-transform",
	"pi-direct-hierarchy",
	"pi-direct-multiturn",
	"pi-direct-leak-audit",
	// PI-INDIRECT: the same strategies delivered through retrieved content.
	"pi-indirect-b64-transform",
	"pi-indirect-hierarchy",
	"pi-indirect-multiturn",
	"pi-indirect-leak-comment",
	// TOOL-UNAUTH: admin-role confusion, encoding, multi-turn, chat-template tokens.
	"tool-unauth-admin-override",
	"tool-unauth-b64",
	"tool-unauth-multiturn",
	"tool-unauth-imstart",
	// EXFIL-FS-NET: admin confusion, encoding, defanged sink, encode-then-send.
	"exfil-admin-override",
	"exfil-b64",
	"exfil-defanged-sink",
	"exfil-encode-then-send",
}

// TestExpandedCorpusReflectionImmune asserts the reflection-immunity invariant
// over the newly added variants specifically, across several seeds. The variants
// broaden strategy depth per scenario; each must still embed only the lowercase
// transform seed (never a canary value), or an echoing target could fake a
// confirmation. This is the correctness cornerstone the whole edifice rests on.
func TestExpandedCorpusReflectionImmune(t *testing.T) {
	for _, seed := range []string{"", "seed-1", "another-seed", "3rd", "édge"} {
		cs := MintCanaries(seed)
		byID := make(map[string]payloadSpec)
		for _, spec := range allPayloadSpecs(cs) {
			byID[spec.id] = spec
		}
		for _, id := range expandedPayloadIDs {
			spec, ok := byID[id]
			if !ok {
				t.Fatalf("seed %q: expanded payload %q missing from corpus", seed, id)
			}
			if err := cs.AssertReflectionImmune([]string{spec.text}); err != nil {
				t.Errorf("seed %q: payload %q not reflection-immune: %v", seed, id, err)
			}
			// Belt and braces: no canary value may appear in the text directly.
			for _, c := range cs.Canaries() {
				if strings.Contains(spec.text, c.Value) {
					t.Errorf("seed %q: payload %q contains canary %q", seed, id, c.Value)
				}
			}
		}
	}
}

// TestPayloadIDUniqueness asserts every payload id is unique across all
// scenarios. A duplicate id would make a trace ambiguous and could collide two
// distinct strategies under one identity.
func TestPayloadIDUniqueness(t *testing.T) {
	cs := MintCanaries("uniqueness-seed")
	seen := make(map[string]bool)
	for _, spec := range allPayloadSpecs(cs) {
		if seen[spec.id] {
			t.Errorf("duplicate payload id %q", spec.id)
		}
		seen[spec.id] = true
	}
	// The expanded set must all be accounted for.
	for _, id := range expandedPayloadIDs {
		if !seen[id] {
			t.Errorf("expanded payload id %q not found in corpus", id)
		}
	}
}

// TestEachScenarioHasExactlyOneControl guards the control gate: a scenario needs
// exactly one benign control, and broadening the attack corpus must not add or
// weaken it. Zero controls leaves the environment unverifiable; more than one
// dilutes the "any signal on a control means the environment is unsound" check.
func TestEachScenarioHasExactlyOneControl(t *testing.T) {
	cs := MintCanaries("control-seed")
	for _, s := range Scenarios() {
		specs := scenarioPayloads(s.ID, cs)
		if len(specs) == 0 {
			continue
		}
		controls := 0
		for _, spec := range specs {
			if spec.control {
				controls++
				if spec.category != CategoryBenignControl {
					t.Errorf("scenario %s: control %q has category %q, want benign_control", s.ID, spec.id, spec.category)
				}
			}
		}
		if controls != 1 {
			t.Errorf("scenario %s has %d controls, want exactly 1", s.ID, controls)
		}
	}
}

// TestEchoOfEveryPayloadNeverSignals is the reflection-immunity property stated
// operationally: a target that reflects a payload verbatim (the worst-case echo)
// can never produce a canary, so it can never be scored a hijack. Asserted over
// the FULL corpus — attacks and controls — across several seeds.
func TestEchoOfEveryPayloadNeverSignals(t *testing.T) {
	for _, seed := range []string{"", "echo-seed", "seed-42"} {
		cs := MintCanaries(seed)
		for _, spec := range allPayloadSpecs(cs) {
			// An echo returns the payload text unchanged in both reply and body.
			if c, ok := cs.Classify(spec.text); ok {
				t.Errorf("seed %q: echo of payload %q classified as canary %q; reflection immunity broken",
					seed, spec.id, c.ID)
			}
		}
	}
}

// TestObfuscatedOverrideAimsAtTransformSignal proves a representative new
// obfuscated override is still aimed at a machine-detectable outcome, not just a
// plausible-looking string. The payload carries the lowercase seed and asks for
// its uppercase form; a model that actually performs that transform emits the
// transform canary value, which Classify detects. We verify the aim without a
// live model by performing the transform ourselves.
func TestObfuscatedOverrideAimsAtTransformSignal(t *testing.T) {
	cs := MintCanaries("aim-seed")
	seed := cs.TransformSeed()

	var text string
	for _, spec := range allPayloadSpecs(cs) {
		if spec.id == "pi-direct-b64-transform" {
			text = spec.text
			break
		}
	}
	if text == "" {
		t.Fatal("representative payload pi-direct-b64-transform not found")
	}
	if !strings.Contains(text, seed) {
		t.Errorf("payload does not carry the transform seed %q", seed)
	}
	if !strings.Contains(strings.ToLower(text), "uppercase") {
		t.Error("payload does not describe an uppercase transform")
	}
	// The signal itself must not be present in what we send (reflection immunity)...
	if strings.Contains(text, cs.transform.Value) {
		t.Fatal("payload leaks the transform canary value")
	}
	// ...but performing the transform an obeying model would perform yields it.
	performed := strings.ToUpper(seed)
	if c, ok := cs.Classify(performed); !ok || c.Kind != CanaryTransform {
		t.Errorf("uppercasing the seed did not produce the transform canary: got %+v ok=%v", c, ok)
	}
}
