package confirm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// AIRules is the set of static rule IDs that assert "untrusted input reaches an
// LLM prompt call". These are the statically-flagged candidates the confirm loop
// tries to dynamically demonstrate. Kept as a map for O(1) membership.
var AIRules = map[string]struct{}{
	"AGENTFLOW-001": {},
	"TAINT-AI-001":  {},
	"AI-PI-001":     {},
	"AI-PI-002":     {},
	"AI-PI-003":     {},
	"AI-PI-004":     {},
}

// IsAIFinding reports whether a finding is an AI prompt-injection candidate.
func IsAIFinding(ruleID string) bool {
	_, ok := AIRules[ruleID]
	return ok
}

// Poster sends a JSON body to a URL and returns the HTTP status and response
// body. It is an interface so tests can drive the driver against an in-process
// handler; the default (HTTPPoster) uses net/http against a real running target.
type Poster interface {
	PostJSON(ctx context.Context, url string, body map[string]string) (status int, respBody string, err error)
}

// HTTPPoster is the default Poster: a plain net/http client. The target is a
// running app the OPERATOR supplied and isolated — nox does not run or sandbox
// it. Read-only from nox's side beyond the attack payloads it deliberately POSTs.
type HTTPPoster struct {
	Client *http.Client
}

// PostJSON implements Poster.
func (p HTTPPoster) PostJSON(ctx context.Context, url string, body map[string]string) (status int, respBody string, err error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

// Config controls a confirmation run.
type Config struct {
	// Target is the base URL of the running target app (e.g. http://localhost:8000).
	Target string
	// Route is the HTTP path to probe (e.g. /chat). If empty, AppSrc is used to
	// recover it per finding.
	Route string
	// Fields are the untrusted request fields to inject into. If empty, AppSrc is
	// used to recover them per finding.
	Fields []string
	// AppSrc, if set, is a Flask-style app source parsed to recover Route/Fields
	// from each finding's handler function when Route/Fields are not given.
	AppSrc string
	// N is the total number of samples for the determinism gate (initial hit +
	// N-1 re-runs). K is the minimum signal hits required to CONFIRM. For a
	// deterministic endpoint K=N; for a real model at temperature>0, K<N.
	N, K  int
	Label string
	// ReplyField is the JSON key in the app's response holding the model reply
	// (default "reply").
	ReplyField string
}

func (c *Config) withDefaults() {
	if c.N <= 0 {
		c.N = 2
	}
	if c.K <= 0 || c.K > c.N {
		c.K = c.N
	}
	if c.ReplyField == "" {
		c.ReplyField = "reply"
	}
	if c.Label == "" {
		c.Label = "app"
	}
}

// Driver runs the confirmation loop.
type Driver struct {
	Poster Poster
	Now    func() time.Time
}

// NewDriver returns a Driver using the default HTTP poster.
func NewDriver() *Driver {
	return &Driver{Poster: HTTPPoster{}, Now: time.Now}
}

// Run selects the AI prompt-injection findings, dedupes shared sinks, and
// produces a confirmation verdict for each. It does NOT assert reflection
// immunity — the caller must call AssertReflectionImmune and fail closed first
// (the CLI does). Run assumes that guarantee holds.
func (d *Driver) Run(ctx context.Context, ff []findings.Finding, cfg Config) (*Report, error) {
	cfg.withDefaults()

	var considered []string
	var ai []findings.Finding
	for i := range ff {
		if IsAIFinding(ff[i].RuleID) {
			considered = append(considered, ff[i].RuleID)
			ai = append(ai, ff[i])
		}
	}

	// Dedupe by (file, line, function): AGENTFLOW-001 and TAINT-AI-001 point at
	// the same sink and would otherwise be probed twice.
	type key struct {
		file string
		line int
		fn   string
	}
	seen := map[key]struct{}{}
	var unique []findings.Finding
	for i := range ai {
		f := ai[i]
		k := key{f.Location.FilePath, f.Location.StartLine, f.Metadata["function"]}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		unique = append(unique, f)
	}

	now := d.Now
	if now == nil {
		now = time.Now
	}
	report := &Report{
		Label:                    cfg.Label,
		Target:                   cfg.Target,
		GeneratedAt:              now().UTC().Format(time.RFC3339),
		ReflectionImmuneAsserted: true,
		AIFindingsConsidered:     considered,
		UniqueSinks:              len(unique),
	}
	for i := range unique {
		report.Results = append(report.Results, d.confirmFinding(ctx, unique[i], cfg))
	}
	return report, nil
}

func (d *Driver) confirmFinding(ctx context.Context, f findings.Finding, cfg Config) FindingVerdict {
	fn := f.Metadata["function"]
	res := FindingVerdict{
		RuleID:      f.RuleID,
		Fingerprint: f.Fingerprint,
		Message:     f.Message,
		Location:    f.Location,
		StaticFlag:  true,
		Function:    fn,
		Verdict:     VerdictUnconfirmed,
	}

	route, fields, err := d.resolveEntryPoint(cfg, fn)
	if err != nil {
		res.Note = err.Error()
		return res
	}
	res.Route = route
	res.RequestFields = fields
	if route == "" || len(fields) == 0 {
		res.Note = fmt.Sprintf("could not recover entry point for function %q", fn)
		return res
	}

	url := strings.TrimRight(cfg.Target, "/") + route
	attempts := d.fireCorpus(ctx, url, fields, cfg.ReplyField)
	res.Attempts = attempts

	// Benign-control gate: the benign payload must NEVER trip a signal. If it
	// does, the environment is unsound and we refuse to confirm anything.
	controlOK := true
	for i := range attempts {
		if attempts[i].Category == CategoryBenignControl && attempts[i].Signal != "" {
			controlOK = false
			break
		}
	}
	res.ControlOK = &controlOK

	// First winning attack attempt (deterministic order: field, then corpus).
	var winner *Attempt
	for i := range attempts {
		a := attempts[i]
		if a.Category != CategoryBenignControl && a.Signal != "" {
			winner = &attempts[i]
			break
		}
	}
	if winner == nil || !controlOK {
		if !controlOK {
			res.Note = "benign control tripped a signal; refusing to confirm (unsound environment)"
		}
		return res
	}

	// Determinism gate: re-fire the exact winning request N-1 more times and
	// require the signal to recur in >= K of N total samples.
	det := d.determinismGate(ctx, url, fields, *winner, cfg)
	if !det.Reproduced {
		res.Note = fmt.Sprintf("winning payload did not reproduce (%d/%d < %d); refusing to CONFIRM",
			det.SignalHits, det.N, det.K)
		return res
	}

	res.Verdict = VerdictConfirmed
	res.DynamicallyConfirmed = true
	res.Evidence = &Evidence{
		Field:         winner.Field,
		Category:      winner.Category,
		PayloadID:     winner.PayloadID,
		Payload:       winner.Payload,
		Signal:        winner.Signal,
		ModelResponse: winner.Reply,
		Determinism:   det,
	}
	return res
}

func (d *Driver) resolveEntryPoint(cfg Config, fn string) (route string, fields []string, err error) {
	// Explicit route/fields always win; recover the rest from --app-src if given.
	route = cfg.Route
	fields = append([]string(nil), cfg.Fields...)
	if (route == "" || len(fields) == 0) && cfg.AppSrc != "" {
		ep, recErr := RecoverEntryPointFromSource(cfg.AppSrc, fn)
		if recErr != nil {
			return "", nil, recErr
		}
		if route == "" {
			route = ep.Route
		}
		if len(fields) == 0 {
			fields = ep.Fields
		}
	}
	if route == "" || len(fields) == 0 {
		return route, fields, fmt.Errorf("no entry point: supply --route and --fields, or --app-src to recover them")
	}
	return route, fields, nil
}

func (d *Driver) fireCorpus(ctx context.Context, url string, fields []string, replyField string) []Attempt {
	sortedFields := append([]string(nil), fields...)
	sort.Strings(sortedFields)
	var attempts []Attempt
	for _, field := range sortedFields {
		for _, p := range corpus {
			attempts = append(attempts, d.fire(ctx, url, fields, field, p, replyField))
		}
	}
	return attempts
}

func (d *Driver) fire(ctx context.Context, url string, allFields []string, targetField string, p Payload, replyField string) Attempt {
	rec := Attempt{Field: targetField, Category: p.Category, PayloadID: p.ID, Payload: p.Text}
	body := buildRequest(allFields, targetField, p.Text)
	status, respBody, err := d.Poster.PostJSON(ctx, url, body)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	reply := extractReply(respBody, replyField)
	rec.Status = status
	rec.Reply = reply
	rec.Signal = ClassifySignal(reply)
	return rec
}

func (d *Driver) determinismGate(ctx context.Context, url string, fields []string, winner Attempt, cfg Config) Determinism {
	det := Determinism{K: cfg.K, N: cfg.N}
	// Sample #1 is the original winning hit.
	hits := 1
	replies := []string{winner.Reply}
	byteIdentical := true
	for i := 1; i < cfg.N; i++ {
		body := buildRequest(fields, winner.Field, winner.Payload)
		_, respBody, err := d.Poster.PostJSON(ctx, url, body)
		reply := extractReply(respBody, cfg.ReplyField)
		if err != nil {
			reply = "<error: " + err.Error() + ">"
		}
		replies = append(replies, reply)
		if ClassifySignal(reply) == winner.Signal {
			hits++
		}
		if reply != winner.Reply {
			byteIdentical = false
		}
	}
	det.SignalHits = hits
	det.ByteIdentical = byteIdentical
	det.Replies = replies
	det.Reproduced = hits >= cfg.K
	return det
}

func buildRequest(fields []string, targetField, payload string) map[string]string {
	obj := make(map[string]string, len(fields))
	for _, f := range fields {
		if f == targetField {
			obj[f] = payload
		} else {
			obj[f] = BenignFiller(f)
		}
	}
	return obj
}

// extractReply pulls the model reply out of the app's JSON response. If the
// response is not JSON or lacks the reply field, the raw body is returned so the
// signal detector still sees whatever the app emitted.
func extractReply(body, replyField string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	raw, ok := m[replyField]
	if !ok {
		return body
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	return s
}
