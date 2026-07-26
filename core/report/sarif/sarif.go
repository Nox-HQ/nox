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
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/compliance"
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
	// Properties is a SARIF property bag. Values are typically strings (e.g.
	// "cwe", "owasp-mcp") but "tags" is a []string so GitHub Code Scanning and
	// registries can read rule categories from the standard taxonomy slot.
	Properties map[string]any `json:"properties,omitempty"`
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
	RuleID    string  `json:"ruleId"`
	RuleIndex int     `json:"ruleIndex"`
	Level     string  `json:"level"`
	Message   Message `json:"message"`
	// omitempty matters: a nil slice would serialise as `"locations": null`,
	// which is no more acceptable to a consumer than an empty uri. A
	// location-less result must have no locations KEY at all.
	Locations    []Location        `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints"`
	// Properties carries the finding's Metadata — the reachability class, the
	// vuln class, and the original-severity downgrade audit trail. Without it a
	// finding downgraded from critical to low showed only "low" in SARIF with
	// no record of the override. Omitted when the finding has no metadata.
	Properties map[string]any `json:"properties,omitempty"`
}

// Location wraps a physical location within a source artifact.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation identifies a file and region within that file.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	// Region is a pointer so a file-level finding (no line) omits it. An empty
	// "region": {} object is rejected by strict SARIF validators, which require
	// a region to carry at least one property.
	Region *Region `json:"region,omitempty"`
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
	for i := range items {
		f := items[i]
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			// This should not happen if buildRuleCatalog is correct, but
			// handle it defensively.
			idx = 0
		}

		// A finding with no file is reported WITHOUT a location, never with an
		// empty one.
		//
		// Some verdicts are about the dependency graph rather than a line of
		// source — a reachability class, or a repository-scoped "no private
		// registry configured" — and arrive with an empty path. Writing that
		// through produced `"uri": ""`, and GitHub rejects the SUBMISSION for
		// it, not the offending result:
		//
		//	locationFromSarifResult: expected artifact location
		//
		// So one location-less finding from one plugin cost a repository its
		// entire code-scanning upload, while the same scan looked clean
		// locally. Any analyzer can emit this shape, so the containment
		// belongs here rather than in each of them.
		//
		// The result is kept: SARIF permits a result with no locations, and
		// dropping it would trade a broken upload for a silently missing
		// verdict — the worse failure for a security tool. An absent array
		// cannot trip "expected artifact location"; an empty-uri entry does.
		var locations []Location
		if f.Location.FilePath != "" {
			phys := PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: encodeURI(f.Location.FilePath)},
			}
			if f.Location.StartLine > 0 {
				phys.Region = &Region{
					StartLine:   f.Location.StartLine,
					StartColumn: f.Location.StartColumn,
					EndLine:     f.Location.EndLine,
					EndColumn:   f.Location.EndColumn,
				}
			}
			locations = []Location{{PhysicalLocation: phys}}
		}

		result := Result{
			RuleID:       f.RuleID,
			RuleIndex:    idx,
			Level:        severityToLevel(f.Severity),
			Message:      Message{Text: f.Message},
			Locations:    locations,
			Fingerprints: map[string]string{"nox/v1": f.Fingerprint},
			Properties:   sarifProperties(f),
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
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// severityToLevel maps a Nox severity to the corresponding SARIF level
// string. Critical and high map to "error", medium to "warning", and low/info
// to "note".
// securitySeverity maps a nox severity to the SARIF `security-severity`
// property GitHub Code Scanning reads. SARIF `level` alone only distinguishes
// error/warning/note, so without this every nox alert arrived with no security
// severity at all: the Code Scanning UI could not filter or sort by severity,
// and severity-based alert rules had nothing to match on.
//
// The value is a CVSS-style score string, banded the way GitHub interprets it:
// >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, < 4.0 low. Info is not a
// security severity and is deliberately omitted (empty) rather than scored 0,
// which would render as "low" and overstate it.
func securitySeverity(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return "9.5"
	case findings.SeverityHigh:
		return "8.0"
	case findings.SeverityMedium:
		return "5.5"
	case findings.SeverityLow:
		return "2.0"
	default:
		return ""
	}
}

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
// encodeURI turns a scanned file path into a valid SARIF artifact URI. Paths
// may contain spaces, '#', '?' and other characters that are invalid in a raw
// URI reference; a bare '#' in particular truncates the path at the fragment.
// Backslashes from Windows runners are normalised to forward slashes first so
// the result is a portable relative URI.
func encodeURI(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	u := url.URL{Path: path}
	return u.String()
}

// sarifProperties projects a finding's metadata into a SARIF property bag,
// returning nil when there is nothing to carry so the field is omitted.
func sarifProperties(f findings.Finding) map[string]any {
	if len(f.Metadata) == 0 {
		return nil
	}
	props := make(map[string]any, len(f.Metadata))
	for k, v := range f.Metadata {
		props[k] = v
	}
	return props
}

func (r *Reporter) buildRuleCatalog(items []findings.Finding) (catalog []ReportingDescriptor, index map[string]int) {
	if r.Rules != nil {
		catalog, index = r.buildCatalogFromRuleSet()
	} else {
		return r.buildCatalogFromFindings(items)
	}

	// Reconcile against the findings actually present. A finding whose rule is
	// not in the RuleSet — every plugin finding (taint, reachability) and any
	// analyzer rule missing from the catalog — would otherwise get RuleIndex 0,
	// a dangling ruleId pointing at whatever rule sorts first. GitHub Code
	// Scanning validates this and rejects the whole upload silently. Synthesise
	// a minimal descriptor for each missing rule ID so the reference resolves.
	for i := range items {
		id := items[i].RuleID
		if _, ok := index[id]; ok || id == "" {
			continue
		}
		index[id] = len(catalog)
		desc := ReportingDescriptor{
			ID:               id,
			Name:             id,
			ShortDescription: Message{Text: items[i].Message},
			DefaultConfiguration: Configuration{
				Level: severityToLevel(items[i].Severity),
			},
		}
		if ss := securitySeverity(items[i].Severity); ss != "" {
			desc.Properties = map[string]any{"security-severity": ss}
		}
		catalog = append(catalog, desc)
	}
	return catalog, index
}

// buildCatalogFromRuleSet creates catalog entries for every rule in the
// RuleSet, sorted by rule ID for deterministic output.
func (r *Reporter) buildCatalogFromRuleSet() (catalog []ReportingDescriptor, index map[string]int) {
	allRules := r.Rules.Rules()

	// Sort rules by ID for deterministic ordering.
	sorted := make([]*rules.Rule, len(allRules))
	copy(sorted, allRules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	catalog = make([]ReportingDescriptor, 0, len(sorted))
	index = make(map[string]int, len(sorted))

	for _, rule := range sorted {
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

		props := make(map[string]any, len(rule.Metadata)+2)
		for k, v := range rule.Metadata {
			props[k] = v
		}
		// Surface OWASP MCP Top 10 control mapping for standards alignment.
		if control := compliance.ControlForRule(rule.ID, rule.Tags); control != "" {
			props["owasp-mcp"] = control
		}
		// Emit rule tags in the standard SARIF taxonomy slot.
		if len(rule.Tags) > 0 {
			props["tags"] = rule.Tags
		}
		// GitHub Code Scanning classifies alerts by this, not by SARIF level.
		if ss := securitySeverity(rule.Severity); ss != "" {
			props["security-severity"] = ss
		}
		if len(props) > 0 {
			desc.Properties = props
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
func (r *Reporter) buildCatalogFromFindings(items []findings.Finding) (catalog []ReportingDescriptor, index map[string]int) {
	// Collect unique rule IDs preserving the first finding's data for each.
	type ruleInfo struct {
		id       string
		severity findings.Severity
		message  string
	}

	seen := make(map[string]struct{})
	var unique []ruleInfo

	for i := range items {
		f := items[i]
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

	catalog = make([]ReportingDescriptor, 0, len(unique))
	index = make(map[string]int, len(unique))

	for _, ri := range unique {
		idx := len(catalog)
		index[ri.id] = idx
		desc := ReportingDescriptor{
			ID:   ri.id,
			Name: ri.id,
			ShortDescription: Message{
				Text: ri.message,
			},
			DefaultConfiguration: Configuration{
				Level: severityToLevel(ri.severity),
			},
		}
		if ss := securitySeverity(ri.severity); ss != "" {
			desc.Properties = map[string]any{"security-severity": ss}
		}
		catalog = append(catalog, desc)
	}

	return catalog, index
}
