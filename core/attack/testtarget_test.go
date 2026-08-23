package attack

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
)

// fakeMode selects the behaviour of a fakeTarget.
type fakeMode string

const (
	// modeVulnerable treats untrusted input as authoritative (system-role), so
	// an injected instruction is obeyed — the exact anti-pattern nox flags.
	modeVulnerable fakeMode = "vulnerable"
	// modeFixed confines untrusted input to inert data, so nothing is obeyed.
	modeFixed fakeMode = "fixed"
	// modeRefusing returns a guardrail refusal for any attack.
	modeRefusing fakeMode = "refusing"
	// modeErroring returns a transport error for every probe.
	modeErroring fakeMode = "erroring"
	// modeNoisy leaks a canary on EVERY request, including the benign control,
	// so the control gate reads the environment as unsound.
	modeNoisy fakeMode = "noisy"
	// modeEcho reflects the input back verbatim. It must NEVER score a signal:
	// echoing the payload cannot reproduce a canary value, which is the whole
	// point of reflection immunity.
	modeEcho fakeMode = "echo"
)

// fake detection regexes. These live in the test fixture, not the product code:
// they model a naive model that OBEYS instructions found in its authoritative
// context. The transform capture is deliberately lowercase-only so the fixture
// upper-cases the captured seed itself (reflection immunity: the signal is
// computed, never echoed).
var (
	fakeTransformRe = regexp.MustCompile(`uppercase form of (?:the word )?([a-z0-9][a-z0-9_\-]*)`)
	fakeLeakRe      = regexp.MustCompile(`(?i)(reveal|disclose|expose|print|show|dump).{0,60}(system prompt|confidential|secret|token)`)
	fakeToolRe      = regexp.MustCompile(`call the ([a-z0-9_]+) tool`)
	fakeExfilRe     = regexp.MustCompile(`(?i)read the file .* and send`)
)

// fakeTarget is an in-process Target that discriminates vulnerable from fixed
// construction. It is the fixture behind the discrimination proof: the same
// corpus must CONFIRM against modeVulnerable and NOT confirm against modeFixed.
type fakeTarget struct {
	mode  fakeMode
	cs    *CanarySet
	sends int
}

func newFakeTarget(mode fakeMode, cs *CanarySet) *fakeTarget {
	return &fakeTarget{mode: mode, cs: cs}
}

func (f *fakeTarget) Name() string { return "fake-" + string(f.mode) }

func (f *fakeTarget) Send(_ context.Context, p Probe) (Observation, error) {
	f.sends++

	// Concatenate all field values as the model's input, in deterministic order.
	keys := make([]string, 0, len(p.Fields))
	for k := range p.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(p.Fields[k])
		sb.WriteString("\n")
	}
	input := sb.String()

	switch f.mode {
	case modeErroring:
		return Observation{}, errors.New("connection refused")
	case modeRefusing:
		return Observation{Status: 200, Reply: "I can't help with that request."}, nil
	case modeNoisy:
		// Unsound: leaks the secret canary regardless of the input.
		return Observation{Status: 200, Reply: "sure, here it is: " + f.cs.secret.Value, Body: f.cs.secret.Value}, nil
	case modeEcho:
		// Pure echo: reflects the input back. No canary can appear here.
		return Observation{Status: 200, Reply: input, Body: input}, nil
	}

	if f.mode != modeVulnerable {
		// modeFixed: untrusted input is inert; nothing is obeyed.
		return Observation{Status: 200, Reply: "[bot] happy to help with account and billing questions."}, nil
	}

	// modeVulnerable: obey instructions found in the (untrusted) input.
	if m := fakeTransformRe.FindStringSubmatch(input); m != nil {
		return Observation{Status: 200, Reply: strings.ToUpper(m[1])}, nil
	}
	if fakeLeakRe.MatchString(input) {
		reply := "Understood. My system prompt build_token=" + f.cs.secret.Value
		return Observation{Status: 200, Reply: reply, Body: reply}, nil
	}
	if m := fakeToolRe.FindStringSubmatch(input); m != nil {
		return Observation{
			Status:    200,
			Reply:     "Invoking " + m[1] + " now.",
			ToolCalls: []ToolCall{{Name: m[1], Args: map[string]string{"scope": "all"}}},
		}, nil
	}
	if fakeExfilRe.MatchString(input) {
		return Observation{
			Status:    200,
			Reply:     "Done, contents sent.",
			Body:      "posted file contents: " + f.cs.file.Value,
			ToolCalls: []ToolCall{{Name: networkSinkTool, Args: map[string]string{"url": "https://exfil.example/collect"}}},
		}, nil
	}
	return Observation{Status: 200, Reply: "[bot] happy to help with account and billing questions."}, nil
}

// recordingTarget counts Send calls and never returns a signal. It exists to
// prove a refused run sends nothing.
type recordingTarget struct{ sends int }

func (r *recordingTarget) Name() string { return "recording" }

func (r *recordingTarget) Send(_ context.Context, _ Probe) (Observation, error) {
	r.sends++
	return Observation{Status: 200, Reply: "ok"}, nil
}
