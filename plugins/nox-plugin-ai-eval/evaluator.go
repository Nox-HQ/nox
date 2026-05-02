// HTTP evaluator. POSTs each corpus entry's prompt to the configured
// chat endpoint and inspects the response for attack-success markers.
//
// The evaluator is deliberately payload-template-driven: every chat
// API has a different request shape (OpenAI uses messages[], some
// custom apps use {"prompt": ...}, others wrap in their own envelope).
// The operator supplies a JSON template with a {{prompt}} placeholder;
// the evaluator substitutes the corpus entry's text on each call.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EvalConfig captures the operator-supplied evaluation parameters.
type EvalConfig struct {
	Endpoint        string
	Method          string // defaults to POST
	PayloadTemplate string // JSON; {{prompt}} replaced per entry
	AuthHeader      string // e.g. "Authorization: Bearer ..."
	ResponsePath    string // dot-path into JSON response (e.g. "choices.0.message.content"); empty = use raw body
	Timeout         time.Duration
	Concurrency     int
	HTTPClient      *http.Client // injectable for tests
}

// Verdict is the outcome of running one corpus entry against the
// endpoint.
type Verdict struct {
	Entry   CorpusEntry
	Success bool
	Marker  string // matched marker text when Success
	Status  int    // HTTP status code
	Error   string // populated on transport / decode failure
	Body    string // truncated response body for audit
}

// Evaluate runs every corpus entry against the configured endpoint
// sequentially (concurrency=1) by default. Concurrency > 1 fans out
// requests but operators should respect target rate limits.
func Evaluate(ctx context.Context, cfg EvalConfig, corpus []CorpusEntry) []Verdict {
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}

	verdicts := make([]Verdict, len(corpus))
	sem := make(chan struct{}, cfg.Concurrency)
	done := make(chan int, len(corpus))

	for i := range corpus {
		i := i
		go func() {
			sem <- struct{}{}
			defer func() { <-sem; done <- i }()
			verdicts[i] = runEntry(ctx, cfg, corpus[i])
		}()
	}

	for range corpus {
		<-done
	}
	return verdicts
}

func runEntry(ctx context.Context, cfg EvalConfig, entry CorpusEntry) Verdict {
	body := strings.ReplaceAll(cfg.PayloadTemplate, "{{prompt}}", jsonEscape(entry.Prompt))

	req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.Endpoint, bytes.NewBufferString(body))
	if err != nil {
		return Verdict{Entry: entry, Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.AuthHeader != "" {
		if name, value, ok := splitHeader(cfg.AuthHeader); ok {
			req.Header.Set(name, value)
		}
	}

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return Verdict{Entry: entry, Error: err.Error()}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return Verdict{Entry: entry, Status: resp.StatusCode, Error: err.Error()}
	}
	body = string(raw)

	answer := body
	if cfg.ResponsePath != "" {
		if extracted, ok := extractJSONPath(body, cfg.ResponsePath); ok {
			answer = extracted
		}
	}

	marker, hit := MatchAny(answer, entry.Markers)
	return Verdict{
		Entry:   entry,
		Success: hit,
		Marker:  marker,
		Status:  resp.StatusCode,
		Body:    truncateBody(answer, 512),
	}
}

func splitHeader(header string) (name, value string, ok bool) {
	idx := strings.IndexByte(header, ':')
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(header[:idx]), strings.TrimSpace(header[idx+1:]), true
}

// jsonEscape produces a JSON-string-safe representation of s without
// the surrounding quotes. Used so the corpus prompt text can be
// injected into a JSON payload template literally.
func jsonEscape(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		return s
	}
	if len(encoded) < 2 {
		return string(encoded)
	}
	return string(encoded[1 : len(encoded)-1])
}

// extractJSONPath walks a dot-separated path into a JSON document and
// returns the final value as a string. Numeric segments are array
// indices; everything else is a key. Returns (value, true) on hit.
func extractJSONPath(jsonBody, path string) (string, bool) {
	var current any
	if err := json.Unmarshal([]byte(jsonBody), &current); err != nil {
		return "", false
	}
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch v := current.(type) {
		case map[string]any:
			next, ok := v[seg]
			if !ok {
				return "", false
			}
			current = next
		case []any:
			idx := atoi(seg)
			if idx < 0 || idx >= len(v) {
				return "", false
			}
			current = v[idx]
		default:
			return "", false
		}
	}
	switch v := current.(type) {
	case string:
		return v, true
	default:
		out, _ := json.Marshal(v)
		return string(out), true
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func truncateBody(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// SummariseVerdicts returns a human-readable counter line for use in
// CLI output / job summaries.
func SummariseVerdicts(verdicts []Verdict) string {
	var ok, fail, errs int
	for i := range verdicts {
		switch {
		case verdicts[i].Error != "":
			errs++
		case verdicts[i].Success:
			ok++
		default:
			fail++
		}
	}
	return fmt.Sprintf("%d attacks: %d succeeded, %d resisted, %d errored", ok+fail+errs, ok, fail, errs)
}
