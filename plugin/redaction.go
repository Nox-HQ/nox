package plugin

import (
	"regexp"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
			regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
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
