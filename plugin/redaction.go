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
			// GitHub token family. The old `gh[ps]_` covered only personal (ghp_)
			// and server (ghs_) tokens and leaked OAuth (gho_), user-to-server
			// (ghu_), and refresh (ghr_) tokens, plus fine-grained PATs
			// (github_pat_), through the primary free-text redaction path.
			regexp.MustCompile(`gh[opsur]_[A-Za-z0-9_]{36,}`),
			regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
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
		// Location.FilePath is a free-text string the plugin fully controls; a
		// secret embedded there (e.g. a URL with credentials) reaches
		// findings.json and SARIF, so it must be scanned like any message field.
		loc, locRedacted := r.redactLocation(f.GetLocation())
		anyRedacted = anyRedacted || locRedacted

		nf := &pluginv1.Finding{
			Id:          f.GetId(),
			RuleId:      f.GetRuleId(),
			Severity:    f.GetSeverity(),
			Confidence:  f.GetConfidence(),
			Location:    loc,
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

	// Redact AI components. Name/Type/Path are plugin-controlled strings copied
	// straight into ai.inventory.json (Path/Name) — a secret routed through any
	// of them would otherwise bypass redaction entirely.
	for _, ac := range resp.GetAiComponents() {
		acName, rn := r.redactString(ac.GetName())
		acType, rt := r.redactString(ac.GetType())
		acPath, rp := r.redactString(ac.GetPath())
		anyRedacted = anyRedacted || rn || rt || rp

		nac := &pluginv1.AIComponent{
			Name: acName,
			Type: acType,
			Path: acPath,
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

	// Redact diagnostics. Source is a plugin-controlled label; redact it too.
	for _, d := range resp.GetDiagnostics() {
		src, srcRedacted := r.redactString(d.GetSource())
		anyRedacted = anyRedacted || srcRedacted

		nd := &pluginv1.Diagnostic{
			Severity: d.GetSeverity(),
			Source:   src,
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
			nfp, fpRed := r.redactString(n.GetFilePath())
			anyRedacted = anyRedacted || fpRed
			nn := &pluginv1.GraphNode{
				Id:       n.GetId(),
				Kind:     n.GetKind(),
				FilePath: nfp,
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

// redactLocation returns a copy of loc with its plugin-controlled FilePath
// scanned for secrets, preserving the line/column fields. nil in ⇒ nil out.
func (r *Redactor) redactLocation(loc *pluginv1.Location) (*pluginv1.Location, bool) {
	if loc == nil {
		return nil, false
	}
	fp, redacted := r.redactString(loc.GetFilePath())
	return &pluginv1.Location{
		FilePath:    fp,
		StartLine:   loc.GetStartLine(),
		EndLine:     loc.GetEndLine(),
		StartColumn: loc.GetStartColumn(),
		EndColumn:   loc.GetEndColumn(),
	}, redacted
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
