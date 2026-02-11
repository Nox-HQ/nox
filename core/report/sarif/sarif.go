// Package sarif generates SARIF 2.1.0 reports from findings.
//
// The Static Analysis Results Interchange Format (SARIF) is an OASIS standard
// for the output of static analysis tools. This package produces SARIF v2.1.0
// documents that are compatible with GitHub Code Scanning, Azure DevOps, and
// other SARIF consumers.
package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

const (
	// sarifVersion is the SARIF specification version produced by this reporter.
	sarifVersion = "2.1.0"

	// sarifSchema is the JSON schema URI for SARIF 2.1.0.
	sarifSchema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

	// toolName is the name of the tool embedded in the SARIF driver.
	toolName = "nox"

	// informationURI is the project URL embedded in the SARIF driver.
	informationURI = "https://github.com/nox-hq/nox"
)

// ---------------------------------------------------------------------------
// SARIF 2.1.0 envelope types
// ---------------------------------------------------------------------------

// Report is the top-level SARIF document containing the schema version
// and one or more analysis runs.
type Report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single invocation of an analysis tool.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that produced the run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver contains identifying information about the tool and the catalog of
// rules it can report on.
type Driver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version"`
	InformationURI string                `json:"informationUri"`
	Rules          []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor defines a single rule in the SARIF rule catalog.
type ReportingDescriptor struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     Message             `json:"shortDescription"`
	FullDescription      *Message            `json:"fullDescription,omitempty"`
	Help                 *MultiformatMessage `json:"help,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration Configuration       `json:"defaultConfiguration"`
	Properties           map[string]string   `json:"properties,omitempty"`
}

// MultiformatMessage is a SARIF message that can carry both plain text and
// markdown representations.
type MultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// Configuration holds the default severity level for a rule.
type Configuration struct {
	Level string `json:"level"`
}

// Message is a SARIF message object containing human-readable text.
type Message struct {
	Text string `json:"text"`
}

// Result is a single finding expressed in SARIF format.
type Result struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex"`
	Level        string            `json:"level"`
	Message      Message           `json:"message"`
	Locations    []Location        `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints"`
}

// Location wraps a physical location within a source artifact.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation identifies a file and region within that file.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation is a URI reference to a source file.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region identifies a contiguous area within an artifact.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// ---------------------------------------------------------------------------
// Reporter implementation
// ---------------------------------------------------------------------------

// Reporter produces SARIF 2.1.0 documents from a FindingSet. It
// implements the report.Reporter interface.
type Reporter struct {
	// ToolVersion is the version string embedded in the SARIF tool driver.
	ToolVersion string

	// Rules is an optional RuleSet used to populate the SARIF rule catalog.
	// When nil, the catalog is derived from the findings themselves.
	Rules *rules.RuleSet
}

// NewReporter returns a Reporter configured with the given tool
// version and optional rule set. The rule set may be nil.
func NewReporter(version string, ruleSet *rules.RuleSet) *Reporter {
	return &Reporter{
		ToolVersion: version,
		Rules:       ruleSet,
	}
}

// Generate builds a complete SARIF 2.1.0 JSON document from the given
// FindingSet. Findings are sorted deterministically before serialization to
// guarantee reproducible output. The returned bytes are pretty-printed JSON.
func (r *Reporter) Generate(fs *findings.FindingSet) ([]byte, error) {
	fs.SortDeterministic()

	items := fs.ActiveFindings()

	// Build the rule catalog and a lookup from rule ID to index.
	ruleCatalog, ruleIndex := r.buildRuleCatalog(items)

	// Map findings to SARIF results.
	results := make([]Result, 0, len(items))
	for _, f := range items {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			// This should not happen if buildRuleCatalog is correct, but
			// handle it defensively.
			idx = 0
		}

		result := Result{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     severityToLevel(f.Severity),
			Message:   Message{Text: f.Message},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: f.Location.FilePath},
						Region: Region{
							StartLine:   f.Location.StartLine,
							StartColumn: f.Location.StartColumn,
							EndLine:     f.Location.EndLine,
							EndColumn:   f.Location.EndColumn,
						},
					},
				},
			},
			Fingerprints: map[string]string{
				"nox/v1": f.Fingerprint,
			},
		}
		results = append(results, result)
	}

	report := Report{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           toolName,
						Version:        r.ToolVersion,
						InformationURI: informationURI,
						Rules:          ruleCatalog,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// WriteToFile generates the SARIF report and writes it to the specified path
// with 0644 permissions. Parent directories must already exist.
func (r *Reporter) WriteToFile(fs *findings.FindingSet, path string) error {
	data, err := r.Generate(fs)
	if err != nil {
		return fmt.Errorf("sarif: generate report: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// severityToLevel maps a Nox severity to the corresponding SARIF level
// string. Critical and high map to "error", medium to "warning", and low/info
// to "note".
func severityToLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	case findings.SeverityLow, findings.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

// buildRuleCatalog constructs the SARIF rules array and a map from rule ID to
// its index within that array. When the reporter has a RuleSet, the catalog is
// populated from it. Otherwise the catalog is derived from the unique rule IDs
// found in the given findings slice.
func (r *Reporter) buildRuleCatalog(items []findings.Finding) ([]ReportingDescriptor, map[string]int) {
	if r.Rules != nil {
		return r.buildCatalogFromRuleSet()
	}
	return r.buildCatalogFromFindings(items)
}

// buildCatalogFromRuleSet creates catalog entries for every rule in the
// RuleSet, sorted by rule ID for deterministic output.
func (r *Reporter) buildCatalogFromRuleSet() ([]ReportingDescriptor, map[string]int) {
	allRules := r.Rules.Rules()

	// Sort rules by ID for deterministic ordering.
	sorted := make([]rules.Rule, len(allRules))
	copy(sorted, allRules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	catalog := make([]ReportingDescriptor, 0, len(sorted))
	index := make(map[string]int, len(sorted))

	for i := range sorted {
		rule := &sorted[i]
		idx := len(catalog)
		index[rule.ID] = idx

		desc := ReportingDescriptor{
			ID:   rule.ID,
			Name: rule.ID,
			ShortDescription: Message{
				Text: rule.Description,
			},
			DefaultConfiguration: Configuration{
				Level: severityToLevel(rule.Severity),
			},
		}

		if len(rule.Metadata) > 0 {
			desc.Properties = rule.Metadata
		}

		// Populate help text from Remediation for GitHub Code Scanning.
		if rule.Remediation != "" {
			helpText := "**Remediation:** " + rule.Remediation
			helpMarkdown := "**Remediation:** " + rule.Remediation
			if len(rule.References) > 0 {
				helpText += "\n\nReferences:\n"
				helpMarkdown += "\n\n**References:**\n"
				for _, ref := range rule.References {
					helpText += "- " + ref + "\n"
					helpMarkdown += "- [" + ref + "](" + ref + ")\n"
				}
			}
			desc.FullDescription = &Message{Text: rule.Description}
			desc.Help = &MultiformatMessage{
				Text:     helpText,
				Markdown: helpMarkdown,
			}
		}

		// Use the first reference as helpUri.
		if len(rule.References) > 0 {
			desc.HelpURI = rule.References[0]
		}

		catalog = append(catalog, desc)
	}

	return catalog, index
}

// buildCatalogFromFindings creates minimal catalog entries derived from the
// unique rule IDs in the findings. The entries are sorted by rule ID.
func (r *Reporter) buildCatalogFromFindings(items []findings.Finding) ([]ReportingDescriptor, map[string]int) {
	// Collect unique rule IDs preserving the first finding's data for each.
	type ruleInfo struct {
		id       string
		severity findings.Severity
		message  string
	}

	seen := make(map[string]struct{})
	var unique []ruleInfo

	for _, f := range items {
		if _, exists := seen[f.RuleID]; exists {
			continue
		}
		seen[f.RuleID] = struct{}{}
		unique = append(unique, ruleInfo{
			id:       f.RuleID,
			severity: f.Severity,
			message:  f.Message,
		})
	}

	// Sort by ID for deterministic output.
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].id < unique[j].id
	})

	catalog := make([]ReportingDescriptor, 0, len(unique))
	index := make(map[string]int, len(unique))

	for _, ri := range unique {
		idx := len(catalog)
		index[ri.id] = idx
		catalog = append(catalog, ReportingDescriptor{
			ID:   ri.id,
			Name: ri.id,
			ShortDescription: Message{
				Text: ri.message,
			},
			DefaultConfiguration: Configuration{
				Level: severityToLevel(ri.severity),
			},
		})
	}

	return catalog, index
}
