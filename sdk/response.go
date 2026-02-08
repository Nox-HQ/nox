package sdk

import (
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
)

// ResponseBuilder provides a fluent API for constructing InvokeToolResponse.
type ResponseBuilder struct {
	resp *pluginv1.InvokeToolResponse
}

// NewResponse creates an empty ResponseBuilder.
func NewResponse() *ResponseBuilder {
	return &ResponseBuilder{resp: &pluginv1.InvokeToolResponse{}}
}

// Finding begins constructing a new finding with the given required fields.
// Call methods on the returned FindingBuilder, then Done() to return here.
func (b *ResponseBuilder) Finding(ruleID string, severity pluginv1.Severity, confidence pluginv1.Confidence, message string) *FindingBuilder {
	f := &pluginv1.Finding{
		RuleId:     ruleID,
		Severity:   severity,
		Confidence: confidence,
		Message:    message,
	}
	return &FindingBuilder{parent: b, finding: f}
}

// Package adds a package dependency to the response.
func (b *ResponseBuilder) Package(name, version, ecosystem string) *ResponseBuilder {
	b.resp.Packages = append(b.resp.Packages, &pluginv1.Package{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
	})
	return b
}

// AIComponent begins constructing a new AI component.
// Call methods on the returned AIComponentBuilder, then Done() to return here.
func (b *ResponseBuilder) AIComponent(name, typ, path string) *AIComponentBuilder {
	comp := &pluginv1.AIComponent{
		Name: name,
		Type: typ,
		Path: path,
	}
	return &AIComponentBuilder{parent: b, comp: comp}
}

// Diagnostic adds a diagnostic message to the response.
func (b *ResponseBuilder) Diagnostic(severity pluginv1.DiagnosticSeverity, message, source string) *ResponseBuilder {
	b.resp.Diagnostics = append(b.resp.Diagnostics, &pluginv1.Diagnostic{
		Severity: severity,
		Message:  message,
		Source:   source,
	})
	return b
}

// Build returns the fully populated InvokeToolResponse.
func (b *ResponseBuilder) Build() *pluginv1.InvokeToolResponse {
	return b.resp
}

// FindingBuilder provides a fluent API for constructing a single Finding.
type FindingBuilder struct {
	parent  *ResponseBuilder
	finding *pluginv1.Finding
}

// At sets the file location for the finding.
func (fb *FindingBuilder) At(filePath string, startLine, endLine int) *FindingBuilder {
	fb.finding.Location = &pluginv1.Location{
		FilePath:  filePath,
		StartLine: int32(startLine),
		EndLine:   int32(endLine),
	}
	return fb
}

// Columns sets the column range. Must be called after At.
func (fb *FindingBuilder) Columns(startCol, endCol int) *FindingBuilder {
	if fb.finding.Location != nil {
		fb.finding.Location.StartColumn = int32(startCol)
		fb.finding.Location.EndColumn = int32(endCol)
	}
	return fb
}

// WithMetadata adds a key-value metadata pair to the finding.
func (fb *FindingBuilder) WithMetadata(key, value string) *FindingBuilder {
	if fb.finding.Metadata == nil {
		fb.finding.Metadata = make(map[string]string)
	}
	fb.finding.Metadata[key] = value
	return fb
}

// WithFingerprint sets the stable fingerprint for deduplication.
func (fb *FindingBuilder) WithFingerprint(fp string) *FindingBuilder {
	fb.finding.Fingerprint = fp
	return fb
}

// Done appends the finding to the parent response and returns the ResponseBuilder.
func (fb *FindingBuilder) Done() *ResponseBuilder {
	fb.parent.resp.Findings = append(fb.parent.resp.Findings, fb.finding)
	return fb.parent
}

// AIComponentBuilder provides a fluent API for constructing a single AIComponent.
type AIComponentBuilder struct {
	parent *ResponseBuilder
	comp   *pluginv1.AIComponent
}

// Detail adds a key-value detail pair to the AI component.
func (ab *AIComponentBuilder) Detail(key, value string) *AIComponentBuilder {
	if ab.comp.Details == nil {
		ab.comp.Details = make(map[string]string)
	}
	ab.comp.Details[key] = value
	return ab
}

// Done appends the AI component to the parent response and returns the ResponseBuilder.
func (ab *AIComponentBuilder) Done() *ResponseBuilder {
	ab.parent.resp.AiComponents = append(ab.parent.resp.AiComponents, ab.comp)
	return ab.parent
}
