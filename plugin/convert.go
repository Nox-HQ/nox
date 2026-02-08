package plugin

import (
	"github.com/felixgeelhaar/hardline/core/analyzers/ai"
	"github.com/felixgeelhaar/hardline/core/analyzers/deps"
	"github.com/felixgeelhaar/hardline/core/findings"
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
)

// --- Proto → Go conversion ---

// ProtoFindingToGo converts a protobuf Finding to the domain Finding type.
func ProtoFindingToGo(pf *pluginv1.Finding) findings.Finding {
	if pf == nil {
		return findings.Finding{}
	}
	f := findings.Finding{
		ID:          pf.GetId(),
		RuleID:      pf.GetRuleId(),
		Severity:    ProtoSeverityToGo(pf.GetSeverity()),
		Confidence:  ProtoConfidenceToGo(pf.GetConfidence()),
		Location:    ProtoLocationToGo(pf.GetLocation()),
		Message:     pf.GetMessage(),
		Fingerprint: pf.GetFingerprint(),
	}
	if m := pf.GetMetadata(); len(m) > 0 {
		f.Metadata = make(map[string]string, len(m))
		for k, v := range m {
			f.Metadata[k] = v
		}
	}
	return f
}

// ProtoLocationToGo converts a protobuf Location to the domain Location type.
// A nil proto Location returns a zero-value Location.
func ProtoLocationToGo(pl *pluginv1.Location) findings.Location {
	if pl == nil {
		return findings.Location{}
	}
	return findings.Location{
		FilePath:    pl.GetFilePath(),
		StartLine:   int(pl.GetStartLine()),
		EndLine:     int(pl.GetEndLine()),
		StartColumn: int(pl.GetStartColumn()),
		EndColumn:   int(pl.GetEndColumn()),
	}
}

// ProtoSeverityToGo maps a protobuf Severity enum to the domain Severity string.
func ProtoSeverityToGo(ps pluginv1.Severity) findings.Severity {
	switch ps {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return findings.SeverityCritical
	case pluginv1.Severity_SEVERITY_HIGH:
		return findings.SeverityHigh
	case pluginv1.Severity_SEVERITY_MEDIUM:
		return findings.SeverityMedium
	case pluginv1.Severity_SEVERITY_LOW:
		return findings.SeverityLow
	case pluginv1.Severity_SEVERITY_INFO:
		return findings.SeverityInfo
	default:
		return findings.SeverityInfo
	}
}

// ProtoConfidenceToGo maps a protobuf Confidence enum to the domain Confidence string.
func ProtoConfidenceToGo(pc pluginv1.Confidence) findings.Confidence {
	switch pc {
	case pluginv1.Confidence_CONFIDENCE_HIGH:
		return findings.ConfidenceHigh
	case pluginv1.Confidence_CONFIDENCE_MEDIUM:
		return findings.ConfidenceMedium
	case pluginv1.Confidence_CONFIDENCE_LOW:
		return findings.ConfidenceLow
	default:
		return findings.ConfidenceLow
	}
}

// ProtoPackageToGo converts a protobuf Package to the domain Package type.
func ProtoPackageToGo(pp *pluginv1.Package) deps.Package {
	if pp == nil {
		return deps.Package{}
	}
	return deps.Package{
		Name:      pp.GetName(),
		Version:   pp.GetVersion(),
		Ecosystem: pp.GetEcosystem(),
	}
}

// ProtoAIComponentToGo converts a protobuf AIComponent to the domain Component type.
func ProtoAIComponentToGo(pac *pluginv1.AIComponent) ai.Component {
	if pac == nil {
		return ai.Component{}
	}
	c := ai.Component{
		Name: pac.GetName(),
		Type: pac.GetType(),
		Path: pac.GetPath(),
	}
	if d := pac.GetDetails(); len(d) > 0 {
		c.Details = make(map[string]string, len(d))
		for k, v := range d {
			c.Details[k] = v
		}
	}
	return c
}

// --- Go → Proto conversion ---

// GoFindingToProto converts a domain Finding to its protobuf representation.
func GoFindingToProto(f findings.Finding) *pluginv1.Finding {
	pf := &pluginv1.Finding{
		Id:          f.ID,
		RuleId:      f.RuleID,
		Severity:    GoSeverityToProto(f.Severity),
		Confidence:  GoConfidenceToProto(f.Confidence),
		Location:    GoLocationToProto(f.Location),
		Message:     f.Message,
		Fingerprint: f.Fingerprint,
	}
	if len(f.Metadata) > 0 {
		pf.Metadata = make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			pf.Metadata[k] = v
		}
	}
	return pf
}

// GoLocationToProto converts a domain Location to its protobuf representation.
func GoLocationToProto(l findings.Location) *pluginv1.Location {
	return &pluginv1.Location{
		FilePath:    l.FilePath,
		StartLine:   int32(l.StartLine),
		EndLine:     int32(l.EndLine),
		StartColumn: int32(l.StartColumn),
		EndColumn:   int32(l.EndColumn),
	}
}

// GoSeverityToProto maps a domain Severity string to the protobuf Severity enum.
func GoSeverityToProto(s findings.Severity) pluginv1.Severity {
	switch s {
	case findings.SeverityCritical:
		return pluginv1.Severity_SEVERITY_CRITICAL
	case findings.SeverityHigh:
		return pluginv1.Severity_SEVERITY_HIGH
	case findings.SeverityMedium:
		return pluginv1.Severity_SEVERITY_MEDIUM
	case findings.SeverityLow:
		return pluginv1.Severity_SEVERITY_LOW
	case findings.SeverityInfo:
		return pluginv1.Severity_SEVERITY_INFO
	default:
		return pluginv1.Severity_SEVERITY_UNSPECIFIED
	}
}

// GoConfidenceToProto maps a domain Confidence string to the protobuf Confidence enum.
func GoConfidenceToProto(c findings.Confidence) pluginv1.Confidence {
	switch c {
	case findings.ConfidenceHigh:
		return pluginv1.Confidence_CONFIDENCE_HIGH
	case findings.ConfidenceMedium:
		return pluginv1.Confidence_CONFIDENCE_MEDIUM
	case findings.ConfidenceLow:
		return pluginv1.Confidence_CONFIDENCE_LOW
	default:
		return pluginv1.Confidence_CONFIDENCE_UNSPECIFIED
	}
}

// GoPackageToProto converts a domain Package to its protobuf representation.
func GoPackageToProto(p deps.Package) *pluginv1.Package {
	return &pluginv1.Package{
		Name:      p.Name,
		Version:   p.Version,
		Ecosystem: p.Ecosystem,
	}
}

// GoAIComponentToProto converts a domain Component to its protobuf representation.
func GoAIComponentToProto(c ai.Component) *pluginv1.AIComponent {
	pac := &pluginv1.AIComponent{
		Name: c.Name,
		Type: c.Type,
		Path: c.Path,
	}
	if len(c.Details) > 0 {
		pac.Details = make(map[string]string, len(c.Details))
		for k, v := range c.Details {
			pac.Details[k] = v
		}
	}
	return pac
}
