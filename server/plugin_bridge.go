package server

import (
	"encoding/json"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/plugin"
)

// JSON serialization types for clean output (not protojson).

type pluginListJSON struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	APIVersion   string           `json:"api_version"`
	Capabilities []capabilityJSON `json:"capabilities"`
}

type capabilityJSON struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Tools       []toolJSON     `json:"tools,omitempty"`
	Resources   []resourceJSON `json:"resources,omitempty"`
}

type toolJSON struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ReadOnly    bool   `json:"read_only"`
}

type resourceJSON struct {
	URITemplate string `json:"uri_template"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
}

type invokeResultJSON struct {
	Findings     []findingJSON     `json:"findings,omitempty"`
	Packages     []packageJSON     `json:"packages,omitempty"`
	AIComponents []aiComponentJSON `json:"ai_components,omitempty"`
	Diagnostics  []diagnosticJSON  `json:"diagnostics,omitempty"`
}

type findingJSON struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id,omitempty"`
	Severity    string            `json:"severity"`
	Confidence  string            `json:"confidence"`
	Location    *locationJSON     `json:"location,omitempty"`
	Message     string            `json:"message,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type locationJSON struct {
	FilePath    string `json:"file_path"`
	StartLine   int32  `json:"start_line,omitempty"`
	EndLine     int32  `json:"end_line,omitempty"`
	StartColumn int32  `json:"start_column,omitempty"`
	EndColumn   int32  `json:"end_column,omitempty"`
}

type packageJSON struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type aiComponentJSON struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Path    string            `json:"path"`
	Details map[string]string `json:"details,omitempty"`
}

type diagnosticJSON struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Source   string `json:"source,omitempty"`
}

// serializePluginList converts plugin info to clean JSON.
func serializePluginList(plugins []plugin.PluginInfo) ([]byte, error) {
	out := make([]pluginListJSON, len(plugins))
	for i, p := range plugins {
		pj := pluginListJSON{
			Name:       p.Name,
			Version:    p.Version,
			APIVersion: p.APIVersion,
		}
		for _, c := range p.Capabilities {
			cj := capabilityJSON{
				Name:        c.Name,
				Description: c.Description,
			}
			for _, t := range c.Tools {
				cj.Tools = append(cj.Tools, toolJSON{
					Name:        t.Name,
					Description: t.Description,
					ReadOnly:    t.ReadOnly,
				})
			}
			for _, r := range c.Resources {
				cj.Resources = append(cj.Resources, resourceJSON{
					URITemplate: r.URITemplate,
					Name:        r.Name,
					Description: r.Description,
					MimeType:    r.MimeType,
				})
			}
			pj.Capabilities = append(pj.Capabilities, cj)
		}
		out[i] = pj
	}
	return json.Marshal(out)
}

// serializeInvokeResult converts a plugin response to clean JSON.
func serializeInvokeResult(resp *pluginv1.InvokeToolResponse) ([]byte, error) {
	result := invokeResultJSON{}

	for _, f := range resp.GetFindings() {
		fj := findingJSON{
			ID:          f.GetId(),
			RuleID:      f.GetRuleId(),
			Severity:    severityToString(f.GetSeverity()),
			Confidence:  confidenceToString(f.GetConfidence()),
			Message:     f.GetMessage(),
			Fingerprint: f.GetFingerprint(),
			Metadata:    f.GetMetadata(),
		}
		if loc := f.GetLocation(); loc != nil {
			fj.Location = &locationJSON{
				FilePath:    loc.GetFilePath(),
				StartLine:   loc.GetStartLine(),
				EndLine:     loc.GetEndLine(),
				StartColumn: loc.GetStartColumn(),
				EndColumn:   loc.GetEndColumn(),
			}
		}
		result.Findings = append(result.Findings, fj)
	}

	for _, p := range resp.GetPackages() {
		result.Packages = append(result.Packages, packageJSON{
			Name:      p.GetName(),
			Version:   p.GetVersion(),
			Ecosystem: p.GetEcosystem(),
		})
	}

	for _, ac := range resp.GetAiComponents() {
		result.AIComponents = append(result.AIComponents, aiComponentJSON{
			Name:    ac.GetName(),
			Type:    ac.GetType(),
			Path:    ac.GetPath(),
			Details: ac.GetDetails(),
		})
	}

	for _, d := range resp.GetDiagnostics() {
		result.Diagnostics = append(result.Diagnostics, diagnosticJSON{
			Severity: diagnosticSeverityToString(d.GetSeverity()),
			Message:  d.GetMessage(),
			Source:   d.GetSource(),
		})
	}

	return json.Marshal(result)
}

// severityToString converts a proto Severity enum to a human-readable string.
func severityToString(s pluginv1.Severity) string {
	switch s {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	case pluginv1.Severity_SEVERITY_HIGH:
		return "high"
	case pluginv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case pluginv1.Severity_SEVERITY_LOW:
		return "low"
	case pluginv1.Severity_SEVERITY_INFO:
		return "info"
	default:
		return "unspecified"
	}
}

// confidenceToString converts a proto Confidence enum to a human-readable string.
func confidenceToString(c pluginv1.Confidence) string {
	switch c {
	case pluginv1.Confidence_CONFIDENCE_HIGH:
		return "high"
	case pluginv1.Confidence_CONFIDENCE_MEDIUM:
		return "medium"
	case pluginv1.Confidence_CONFIDENCE_LOW:
		return "low"
	default:
		return "unspecified"
	}
}

// diagnosticSeverityToString converts a proto DiagnosticSeverity enum to a string.
func diagnosticSeverityToString(s pluginv1.DiagnosticSeverity) string {
	switch s {
	case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR:
		return "error"
	case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING:
		return "warning"
	case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO:
		return "info"
	default:
		return "unspecified"
	}
}
