package plugin

import (
	"regexp"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

const redactedPlaceholder = "[REDACTED]"

// Redactor scans plugin output for secret patterns and replaces matches.
type Redactor struct {
	patterns []*regexp.Regexp
}

// NewRedactor creates a Redactor with common secret detection patterns.
// These patterns are intentionally duplicated from core/analyzers/secrets
// to avoid coupling core/ and plugin/ packages.
func NewRedactor() *Redactor {
	return &Redactor{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`),
			regexp.MustCompile(`-{5}BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{5}`),
			regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9]{16,}['"]`),
		},
	}
}

// RedactResponse returns a new InvokeToolResponse with secrets replaced by
// [REDACTED]. Returns (nil, false) if resp is nil. The bool indicates whether
// any redaction was performed.
func (r *Redactor) RedactResponse(resp *pluginv1.InvokeToolResponse) (*pluginv1.InvokeToolResponse, bool) {
	if resp == nil {
		return nil, false
	}

	anyRedacted := false
	out := &pluginv1.InvokeToolResponse{}

	// Redact findings.
	for _, f := range resp.GetFindings() {
		nf := &pluginv1.Finding{
			Id:          f.GetId(),
			RuleId:      f.GetRuleId(),
			Severity:    f.GetSeverity(),
			Confidence:  f.GetConfidence(),
			Location:    f.GetLocation(),
			Fingerprint: f.GetFingerprint(),
		}

		msg, redacted := r.redactString(f.GetMessage())
		nf.Message = msg
		anyRedacted = anyRedacted || redacted

		if f.GetMetadata() != nil {
			nf.Metadata = make(map[string]string, len(f.GetMetadata()))
			for k, v := range f.GetMetadata() {
				rv, red := r.redactString(v)
				nf.Metadata[k] = rv
				anyRedacted = anyRedacted || red
			}
		}

		out.Findings = append(out.Findings, nf)
	}

	// Copy packages as-is (structured identifiers, not free text).
	out.Packages = resp.GetPackages()

	// Redact AI components.
	for _, ac := range resp.GetAiComponents() {
		nac := &pluginv1.AIComponent{
			Name: ac.GetName(),
			Type: ac.GetType(),
			Path: ac.GetPath(),
		}

		if ac.GetDetails() != nil {
			nac.Details = make(map[string]string, len(ac.GetDetails()))
			for k, v := range ac.GetDetails() {
				rv, red := r.redactString(v)
				nac.Details[k] = rv
				anyRedacted = anyRedacted || red
			}
		}

		out.AiComponents = append(out.AiComponents, nac)
	}

	// Redact diagnostics.
	for _, d := range resp.GetDiagnostics() {
		nd := &pluginv1.Diagnostic{
			Severity: d.GetSeverity(),
			Source:   d.GetSource(),
		}

		msg, redacted := r.redactString(d.GetMessage())
		nd.Message = msg
		anyRedacted = anyRedacted || redacted

		out.Diagnostics = append(out.Diagnostics, nd)
	}

	// Redact enrichments.
	//
	// These carry free-text title and body (markdown explanations, triage
	// rationale) plus arbitrary metadata, so they need redacting like findings
	// do. They were previously not copied at all: rebuilding the response
	// dropped every enrichment and graph a plugin produced, silently. The
	// post-scan path masked it by bypassing redaction entirely, so the loss
	// only showed on the main scan path — reachability annotations and call
	// graphs vanished with no error.
	for _, e := range resp.GetEnrichments() {
		ne := &pluginv1.Enrichment{
			FindingFingerprint: e.GetFindingFingerprint(),
			Kind:               e.GetKind(),
			Confidence:         e.GetConfidence(),
			Source:             e.GetSource(),
		}

		title, redacted := r.redactString(e.GetTitle())
		ne.Title = title
		anyRedacted = anyRedacted || redacted

		body, redacted := r.redactString(e.GetBody())
		ne.Body = body
		anyRedacted = anyRedacted || redacted

		if e.GetMetadata() != nil {
			ne.Metadata = make(map[string]string, len(e.GetMetadata()))
			for k, v := range e.GetMetadata() {
				rv, red := r.redactString(v)
				ne.Metadata[k] = rv
				anyRedacted = anyRedacted || red
			}
		}

		out.Enrichments = append(out.Enrichments, ne)
	}

	// Redact graphs. Node and edge identifiers are structural, but labels and
	// the graph description are free text a plugin composed.
	for _, g := range resp.GetGraphs() {
		ng := &pluginv1.Graph{Name: g.GetName()}

		desc, redacted := r.redactString(g.GetDescription())
		ng.Description = desc
		anyRedacted = anyRedacted || redacted

		for _, n := range g.GetNodes() {
			nn := &pluginv1.GraphNode{
				Id:       n.GetId(),
				Kind:     n.GetKind(),
				FilePath: n.GetFilePath(),
			}
			label, red := r.redactString(n.GetLabel())
			nn.Label = label
			anyRedacted = anyRedacted || red
			nn.Properties, red = r.redactMap(n.GetProperties())
			anyRedacted = anyRedacted || red
			ng.Nodes = append(ng.Nodes, nn)
		}

		for _, e := range g.GetEdges() {
			ne := &pluginv1.GraphEdge{
				Source: e.GetSource(),
				Target: e.GetTarget(),
				Kind:   e.GetKind(),
			}
			label, red := r.redactString(e.GetLabel())
			ne.Label = label
			anyRedacted = anyRedacted || red
			ne.Properties, red = r.redactMap(e.GetProperties())
			anyRedacted = anyRedacted || red
			ng.Edges = append(ng.Edges, ne)
		}

		out.Graphs = append(out.Graphs, ng)
	}

	return out, anyRedacted
}

// redactMap redacts every value in a string map, preserving nil so an absent
// map does not become an empty one.
func (r *Redactor) redactMap(in map[string]string) (map[string]string, bool) {
	if in == nil {
		return nil, false
	}
	out := make(map[string]string, len(in))
	anyRedacted := false
	for k, v := range in {
		rv, red := r.redactString(v)
		out[k] = rv
		anyRedacted = anyRedacted || red
	}
	return out, anyRedacted
}

// redactString replaces all secret patterns in s with [REDACTED].
func (r *Redactor) redactString(s string) (string, bool) {
	result := s
	redacted := false
	for _, p := range r.patterns {
		if p.MatchString(result) {
			result = p.ReplaceAllString(result, redactedPlaceholder)
			redacted = true
		}
	}
	return result, redacted
}
