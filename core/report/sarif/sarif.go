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

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/compliance"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
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
	Tool Tool `json:"tool"`
	// Invocations carries what the run could and could not establish. SARIF has
	// no slot for "this analysis was never able to run here", so the standard's
	// nearest honest home for it is a tool execution notification — see
	// buildInvocations.
	Invocations []Invocation `json:"invocations,omitempty"`
	Results     []Result     `json:"results"`
}

// Invocation describes one execution of the tool, per SARIF §3.20.
type Invocation struct {
	// ExecutionSuccessful is required by the schema. It is true whenever nox
	// produced a report at all: a capability nox never had is not a failed
	// execution, and saying otherwise would turn every installation without a
	// call graph into a broken run.
	ExecutionSuccessful bool `json:"executionSuccessful"`
	// ToolExecutionNotifications reports conditions about the run itself
	// rather than about the code — SARIF §3.20.21.
	ToolExecutionNotifications []Notification `json:"toolExecutionNotifications,omitempty"`
}

// Notification is a SARIF notification object (§3.58).
type Notification struct {
	Descriptor *ReportingDescriptorReference `json:"descriptor,omitempty"`
	Level      string                        `json:"level"`
	Message    Message                       `json:"message"`
}

// ReportingDescriptorReference identifies the notification's kind (§3.52), so a
// consumer can group or filter on the id rather than parse the message text.
type ReportingDescriptorReference struct {
	ID string `json:"id"`
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

	// Capabilities is the scan's analysis capability matrix, rendered as tool
	// execution notifications. It takes the type core/report already derives so
	// that findings.sarif and findings.json cannot disagree about what nox
	// could establish — one derivation, two artifacts. Nil for a report with no
	// scan behind it, which emits no invocations at all rather than an empty
	// claim of full coverage.
	Capabilities []report.CapabilityCoverage

	// NotScanned lists the scopes a scoped scan left out, rendered as
	// execution notifications beside the capability ones: Code Scanning shows
	// a secrets-only run with no dependency alerts exactly like a full run
	// whose dependencies are clean, and this is the difference.
	NotScanned []string

	// CompetenceProfiles resolves each finding's CompetenceProfile ID into the
	// capabilities that did not conclude about it.
	//
	// SARIF gets the RESOLVED list rather than the ID. A profile reference is a
	// nox concept that a SARIF consumer has no way to look up — Code Scanning
	// reads the result, not nox's meta block — so shipping the identifier alone
	// would be shipping nothing.
	CompetenceProfiles []capability.Profile

	// Declared is the scan's rule catalog, read only for each rule's declared
	// severity, by a surface that does not embed the catalog (Rules nil).
	//
	// Which descriptor a result points at depends on it: a finding at its rule's
	// declared severity is reported under the rule's own id, any other under a
	// severity variant (see resultRuleID). Without it a surface would have to
	// guess the rule's severity from the findings, and the SARIF from the CLI
	// and from MCP would name the same finding differently.
	Declared *rules.RuleSet
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
		ruleID := r.resultRuleID(f)
		idx, ok := ruleIndex[ruleID]
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
			RuleID:       ruleID,
			RuleIndex:    idx,
			Level:        severityToLevel(f.Severity),
			Message:      Message{Text: f.Message},
			Locations:    locations,
			Fingerprints: map[string]string{"nox/v1": f.Fingerprint},
			Properties:   r.resultProperties(f),
		}
		results = append(results, result)
	}

	doc := Report{
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
				Invocations: r.buildInvocations(),
				Results:     results,
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// buildInvocations renders the capability matrix as tool execution
// notifications — the one slot SARIF has for a statement about the RUN rather
// than about the code.
//
// It reports only the questions that went unanswered, and that asymmetry is
// deliberate. A SARIF consumer already sees what nox found; nothing in the
// format tells it what nox was never able to look for, so a scan from an
// installation with no call graph and a scan from one that has a call graph and
// found nothing clean arrive identical. Code Scanning shows both as green.
// These notifications are the difference, and they are the reason this milestone
// exists: the state was already computed, and it died at the artifact boundary.
//
// Every notification is level "note". None of these is an execution failure — a
// capability nobody implements is a permanent, honest limit — and levelling a
// limit as a warning is how a signal gets filtered out by the people who most
// need to read it.
func (r *Reporter) buildInvocations() []Invocation {
	if len(r.Capabilities) == 0 && len(r.NotScanned) == 0 {
		return nil
	}
	var notes []Notification
	for _, s := range r.NotScanned {
		notes = append(notes, Notification{
			Descriptor: &ReportingDescriptorReference{ID: "nox/scope/not-scanned"},
			Level:      "note",
			Message: Message{Text: fmt.Sprintf("%s: not scanned in this run (--only/--skip or scan.scopes). "+
				"No result here means nox did not look, not that there is nothing to find.", s)},
		})
	}
	for _, c := range r.Capabilities {
		var id, text string
		switch {
		case !c.Provided:
			id = "nox/capability/unsupported"
			text = fmt.Sprintf("%s: no implementation on this installation. "+
				"This scan could not ask the question, and its silence about it is not an all-clear.", c.Capability)
		case c.Answered == 0 && c.Inconclusive == 0:
			id = "nox/capability/not-evaluated"
			text = fmt.Sprintf("%s: available but evaluated nothing in this scan. "+
				"No result here means the question was not put, not that it was answered.", c.Capability)
		case c.Answered == 0:
			id = "nox/capability/inconclusive"
			text = fmt.Sprintf("%s: evaluated %d subject(s) and determined none of them.", c.Capability, c.Inconclusive)
		case c.Inconclusive > 0:
			id = "nox/capability/inconclusive"
			text = fmt.Sprintf("%s: answered %d subject(s); %d could not be determined.",
				c.Capability, c.Answered, c.Inconclusive)
		default:
			// Answered everything it was asked. Nothing to report.
			continue
		}
		notes = append(notes, Notification{
			Descriptor: &ReportingDescriptorReference{ID: id},
			Level:      "note",
			Message:    Message{Text: text},
		})
	}
	if len(notes) == 0 {
		return nil
	}
	return []Invocation{{ExecutionSuccessful: true, ToolExecutionNotifications: notes}}
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

// resultProperties is sarifProperties plus this finding's own competence.
//
// The run-level notifications say what the scan could not establish anywhere.
// This says what it did not establish about THIS alert, which is the question
// somebody triaging one alert in the Code Scanning UI is actually asking — and
// the run-level answer forces them to assume the best case for every alert.
//
// The list is resolved to capability names, never a profile ID: nothing on the
// consuming side can look an ID up.
func (r *Reporter) resultProperties(f findings.Finding) map[string]any {
	props := sarifProperties(f)
	gaps := r.gapsFor(f.CompetenceProfile)
	if len(gaps) == 0 {
		return props
	}
	if props == nil {
		props = make(map[string]any, 1)
	}
	names := make([]string, 0, len(gaps))
	for _, g := range gaps {
		names = append(names, string(g.Capability)+"="+string(g.State))
	}
	props["nox_unevaluated"] = strings.Join(names, ",")
	return props
}

// gapsFor resolves a competence profile ID. An ID naming no profile resolves to
// nothing rather than to an empty gap list, because an empty gap list means
// every question was answered — the one claim an unresolvable reference must
// never be turned into.
func (r *Reporter) gapsFor(id string) []capability.Gap {
	if id == "" {
		return nil
	}
	for i := range r.CompetenceProfiles {
		if r.CompetenceProfiles[i].ID == id {
			return r.CompetenceProfiles[i].Gaps
		}
	}
	return nil
}

// resultRuleID names the rule descriptor a finding is reported under.
//
// GitHub Code Scanning rates an alert by its descriptor's security-severity
// alone; a result's level never moves it between critical, high, medium and
// low. So a descriptor can carry one severity, and a finding at any other
// severity needs a descriptor of its own: `<rule>/<severity>`, the hierarchical
// form SARIF §3.27.5 gives a sub-rule.
//
// A finding at its rule's declared severity keeps the rule's plain id, so the
// alerts nothing re-rated keep their identity. A rule nox declares nothing
// about (a plugin's) has no severity of its own to compare with, so every one
// of its findings is named by severity.
//
// The answer depends on the finding and the declared catalog only. Deriving a
// rule's severity from the findings instead, as this reporter once did, let
// one info finding sorting first strip the rating from every real one, and
// made each alert's rating hinge on what else the scan happened to find.
func (r *Reporter) resultRuleID(f findings.Finding) string {
	if f.RuleID == "" || !f.Severity.IsValid() {
		return f.RuleID
	}
	if rule := r.declared(f.RuleID); rule != nil && rule.Severity == f.Severity {
		return f.RuleID
	}
	return f.RuleID + "/" + string(f.Severity)
}

// declared returns the catalog's rule for id, or nil.
func (r *Reporter) declared(id string) *rules.Rule {
	for _, rs := range []*rules.RuleSet{r.Rules, r.Declared} {
		if rs == nil {
			continue
		}
		if rule, ok := rs.ByID(id); ok {
			return rule
		}
	}
	return nil
}

// buildRuleCatalog constructs the SARIF rules array and a map from descriptor
// id to its index. With an embedded catalog (Rules) every rule is listed at its
// declared severity, in id order; after it, and only when a result needs one,
// comes each severity variant and each descriptor for a rule the catalog does
// not hold, also in id order.
func (r *Reporter) buildRuleCatalog(items []findings.Finding) (catalog []ReportingDescriptor, index map[string]int) {
	index = make(map[string]int)
	if r.Rules != nil {
		all := r.Rules.Rules()
		sorted := make([]*rules.Rule, len(all))
		copy(sorted, all)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
		catalog = make([]ReportingDescriptor, 0, len(sorted))
		for _, rule := range sorted {
			index[rule.ID] = len(catalog)
			catalog = append(catalog, ruleDescriptor(rule))
		}
	}

	var extra []ReportingDescriptor
	for i := range items {
		f := items[i]
		id := r.resultRuleID(f)
		if _, ok := index[id]; ok || id == "" {
			continue
		}
		index[id] = -1 // placeholder until the extras are sorted
		extra = append(extra, r.variantDescriptor(f, id))
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].ID < extra[j].ID })
	for _, d := range extra {
		index[d.ID] = len(catalog)
		catalog = append(catalog, d)
	}
	return catalog, index
}

// variantDescriptor describes a descriptor id that is not a declared rule at
// its own severity: a severity variant of a declared rule, a declared rule
// listed because a result points at it (no embedded catalog), or a rule nox
// declares nothing about.
func (r *Reporter) variantDescriptor(f findings.Finding, id string) ReportingDescriptor {
	rule := r.declared(f.RuleID)
	if rule != nil && id == f.RuleID {
		return ruleDescriptor(rule)
	}
	var desc ReportingDescriptor
	if rule != nil {
		desc = ruleDescriptor(rule)
	} else {
		desc = ReportingDescriptor{ShortDescription: Message{Text: f.Message}}
	}
	desc.ID = id
	desc.Name = id
	desc.DefaultConfiguration = Configuration{Level: severityToLevel(f.Severity)}
	props := make(map[string]any, len(desc.Properties)+2)
	for k, v := range desc.Properties {
		props[k] = v
	}
	delete(props, "security-severity")
	if ss := securitySeverity(f.Severity); ss != "" {
		props["security-severity"] = ss
	}
	if id != f.RuleID {
		props["parent-rule"] = f.RuleID
		if rule != nil {
			desc.ShortDescription = Message{Text: fmt.Sprintf("%s (reported at %s)", rule.Description, f.Severity)}
		}
	}
	desc.Properties = props
	return desc
}

// ruleDescriptor describes a declared rule at its declared severity.
func ruleDescriptor(rule *rules.Rule) ReportingDescriptor {
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
	return desc
}
