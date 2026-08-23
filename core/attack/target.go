package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ToolCall records one tool invocation observed in a target's response. It is the
// trace channel ToolTraceOracle reads: a value here means the target actually
// called a tool, which an echoing target cannot fabricate.
type ToolCall struct {
	// Name is the invoked tool's name.
	Name string `json:"name"`
	// Args are the invocation arguments, if the target reported them.
	Args map[string]string `json:"args,omitempty"`
}

// Probe is a single request to send to a target: the route, the field values
// (one carrying the payload, the rest benign), and the payload's identity.
type Probe struct {
	// Route is the target path to send to.
	Route string `json:"route"`
	// Fields are the request field values.
	Fields map[string]string `json:"fields"`
	// PayloadID identifies the payload under test.
	PayloadID string `json:"payload_id"`
	// Category is the payload category.
	Category string `json:"category"`
}

// Observation is what a target returned for a probe. Oracles read it; nothing
// else about the target is trusted.
type Observation struct {
	// Status is the HTTP-style status code, or 0 if not applicable.
	Status int `json:"status"`
	// Reply is the extracted model reply text.
	Reply string `json:"reply"`
	// Body is the raw response body, scanned for canaries reaching a sink.
	Body string `json:"body,omitempty"`
	// ToolCalls are the tool invocations the response reported.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// Err is a transport-level error string, or "" on success.
	Err string `json:"err,omitempty"`
}

// Target is something a probe can be sent to. It is an interface so a run can be
// driven against a real HTTP app, a safe simulator, or an in-process fake in
// tests, all identically.
type Target interface {
	// Name identifies the target for reporting.
	Name() string
	// Send delivers a probe and returns what was observed.
	Send(ctx context.Context, p Probe) (Observation, error)
}

// HTTPTarget sends probes as JSON POSTs to a running app. The app is one the
// OPERATOR supplied and isolated; nox does not run or sandbox it. It reaches the
// network, so a run may use it only under a profile that allows traffic.
type HTTPTarget struct {
	baseURL    string
	replyField string
	client     *http.Client
}

// NewHTTPTarget returns an HTTPTarget posting to baseURL and reading replyField
// from each JSON response. A zero replyField defaults to "reply"; a non-positive
// timeout defaults to 15s.
func NewHTTPTarget(baseURL, replyField string, timeout time.Duration) *HTTPTarget {
	if replyField == "" {
		replyField = "reply"
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPTarget{
		baseURL:    strings.TrimRight(baseURL, "/"),
		replyField: replyField,
		client:     &http.Client{Timeout: timeout},
	}
}

// Name returns the target's base URL.
func (h *HTTPTarget) Name() string { return h.baseURL }

// Send posts the probe's fields as JSON and returns the observation. Transport
// errors are returned both as the error and on Observation.Err so a caller that
// aggregates observations still sees the failure.
func (h *HTTPTarget) Send(ctx context.Context, p Probe) (Observation, error) {
	url := h.baseURL + p.Route
	raw, err := json.Marshal(p.Fields)
	if err != nil {
		return Observation{Err: err.Error()}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return Observation{Err: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return Observation{Err: err.Error()}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Observation{Status: resp.StatusCode, Err: err.Error()}, err
	}
	body := string(data)
	return Observation{
		Status:    resp.StatusCode,
		Body:      body,
		Reply:     extractField(body, h.replyField),
		ToolCalls: extractToolCalls(body),
	}, nil
}

// SimTarget is the safe-profile target: it records intent and sends nothing. A
// run using it can never reach a real system, so no oracle can ever score a
// violation — a safe run derives to PLAUSIBLE at most.
type SimTarget struct{}

// NewSimTarget returns a SimTarget.
func NewSimTarget() *SimTarget { return &SimTarget{} }

// Name returns a fixed identifier.
func (s *SimTarget) Name() string { return "sim" }

// Send returns an empty observation without sending anything.
func (s *SimTarget) Send(_ context.Context, _ Probe) (Observation, error) {
	return Observation{}, nil
}

// isSimTarget reports whether t is the non-networking simulator. It is how Run
// tells "sends nothing" from "sends traffic" without widening the Target
// interface.
func isSimTarget(t Target) bool {
	_, ok := t.(*SimTarget)
	return ok
}

// extractField pulls a string field out of a JSON body.
//
// A body that is not a JSON object falls back to the raw text: a plain-text
// target has no field to name, and whatever it emitted IS the reply.
//
// A body that IS a JSON object but lacks the named field returns "" rather than
// the raw body. The difference matters because Observation.Reply is what the
// refusal oracle reads, and returning the serialized JSON there let a misnamed
// --reply-field pattern-match refusal phrasing anywhere in the response and
// report PREVENTED — nox reading its own blindness as a defense. Canary
// detection is unaffected: the canary oracle scans Body as well as Reply, so a
// leak still trips regardless of which key carried it.
func extractField(body, field string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	return s
}

// extractToolCalls parses an optional "tool_calls" array from a JSON body. A
// target that does not report tool calls simply yields none; nothing is inferred
// from the reply text.
func extractToolCalls(body string) []ToolCall {
	var m struct {
		ToolCalls []ToolCall `json:"tool_calls"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return nil
	}
	return m.ToolCalls
}

// sortedCopy returns a sorted copy of ss, leaving the input untouched so probe
// ordering is deterministic without mutating the caller's slice.
func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

// makeProbe builds a probe that places spec.text in the target field and benign
// fillers in the rest.
func makeProbe(route string, fields []string, target string, spec payloadSpec) Probe {
	m := make(map[string]string, len(fields)+1)
	placed := false
	for _, f := range fields {
		if f == target {
			m[f] = spec.text
			placed = true
		} else {
			m[f] = benignFiller(f)
		}
	}
	// The target field must always carry the payload, even when the caller's
	// field list does not mention it — a replay or a regression case names the
	// field the exploit was found in, and that name may not be in the run-wide
	// default list.
	//
	// Without this the payload is silently dropped: the probe goes out carrying
	// only benign filler, produces no signal, and "did not reproduce" gets
	// reported for an attack that was never actually fired. A probe that omits
	// its own payload is not a probe.
	if target != "" && !placed {
		m[target] = spec.text
	}
	return Probe{Route: route, Fields: m, PayloadID: spec.id, Category: spec.category}
}
