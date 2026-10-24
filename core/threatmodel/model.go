// Package threatmodel turns the evidence a nox scan already produced into the
// raw material of a threat model: the elements of the system nox can see, the
// data flows and trust boundaries between them, and, per element, what nox
// knows against each STRIDE category.
//
// It is deliberately small, offline and deterministic, and it follows the shape
// of core/compliance/iso27001. It reads findings.json (with the routes and
// leads recorded in it), ai.inventory.json and an SBOM, never scans, never
// touches the network and never reads a clock. The same inputs produce the same
// bytes.
//
// It also deliberately cannot say that a system is safe. A threat model is made
// by people who know the business logic, the deployment and the identity
// provider, none of which a scanner can see; what a scan can offer is the
// evidence it has, attached to the thing it is about, with an explicit
// statement of what it does not cover. So every threat statement cites the
// scan output it comes from, a cell nox has nothing for says so ("not
// evidenced") instead of reading as clear, and a test pins that no rendered
// output uses a word that would claim a threat does not exist or has been dealt with.
//
// Nothing here is invented. An element exists because a route, an inventory
// entry, a dependency or a finding says it does; a flow exists because
// something in the scan joins its two ends; a STRIDE cell has evidence because
// a finding, a lead or a recorded observation says so. The nox/threat-model
// plugin, which flagged `if token == ""` as an authentication bypass, was
// retired for doing the opposite.
package threatmodel

// SchemaVersion identifies the model.json format.
const SchemaVersion = "1.0.0"

// ReportKind is the value of Meta.Report. A later run reads a model.json back
// (`nox model --previous`) and refuses anything else.
const ReportKind = "threat-model"

// Notice is printed in every rendering. It avoids the vocabulary of assurance
// on purpose: nothing here is a verdict.
const Notice = "This is a system description and threat evidence assembled from an automated scan, offered as input to " +
	"a threat model that people make. It lists what nox can evidence and what it cannot see. A category with no evidence " +
	"is not evidenced either way, and that is not an assurance. Nothing here decides whether a threat is real or what should be done about it."

// ShortNotice is the one-line form of Notice, for the terminal.
const ShortNotice = "Evidence only: a cell with no evidence is not evidenced either way, and nothing here says a threat does not exist."

// Category is one STRIDE threat category.
type Category string

// The six STRIDE categories, in the order they are always rendered.
const (
	Spoofing              Category = "spoofing"
	Tampering             Category = "tampering"
	Repudiation           Category = "repudiation"
	InformationDisclosure Category = "information_disclosure"
	DenialOfService       Category = "denial_of_service"
	ElevationOfPrivilege  Category = "elevation_of_privilege"
)

// Categories lists the STRIDE categories in rendering order.
var Categories = []Category{
	Spoofing, Tampering, Repudiation, InformationDisclosure, DenialOfService, ElevationOfPrivilege,
}

// Label is the plain-language heading for a category.
func (c Category) Label() string {
	switch c {
	case Spoofing:
		return "Spoofing"
	case Tampering:
		return "Tampering"
	case Repudiation:
		return "Repudiation"
	case InformationDisclosure:
		return "Information disclosure"
	case DenialOfService:
		return "Denial of service"
	case ElevationOfPrivilege:
		return "Elevation of privilege"
	}
	return string(c)
}

// Letter is the one-letter STRIDE abbreviation.
func (c Category) Letter() string {
	switch c {
	case Spoofing:
		return "S"
	case Tampering:
		return "T"
	case Repudiation:
		return "R"
	case InformationDisclosure:
		return "I"
	case DenialOfService:
		return "D"
	case ElevationOfPrivilege:
		return "E"
	}
	return "?"
}

// Status describes the EVIDENCE nox holds for one cell, never the threat.
//
// It reuses the vocabulary of core/compliance/iso27001, minus the value that
// reads as support: there is no state here that means "this is handled",
// because a scanner cannot know that.
type Status string

const (
	// OpenIssues means the cell has active findings.
	OpenIssues Status = "open_issues"
	// LeadsToVerify means nox saw something worth checking by hand or at
	// runtime that is not a finding: an authorization lead, or a route with no
	// authentication middleware visible.
	LeadsToVerify Status = "leads_to_verify"
	// LimitedEvidence means nox holds context for the cell, such as the
	// middleware it can see on a route or the capabilities an agent holds, but
	// nothing open. It does not mean the cell is covered.
	LimitedEvidence Status = "limited_evidence"
	// NotEvidenced means nox has no evidence either way.
	NotEvidenced Status = "not_evidenced"
)

// statusRank orders statuses from most to least pressing, for choosing a
// cell's status and sorting.
func statusRank(s Status) int {
	switch s {
	case OpenIssues:
		return 0
	case LeadsToVerify:
		return 1
	case LimitedEvidence:
		return 2
	}
	return 3
}

// Zone names the trust zone an element sits in. Crossing between zones is what
// a boundary describes.
type Zone string

// Trust zones.
const (
	ZoneUntrusted   Zone = "untrusted"
	ZoneApplication Zone = "application"
	ZoneModel       Zone = "model_provider"
	ZoneHost        Zone = "host"
	ZoneData        Zone = "data"
	ZoneThirdParty  Zone = "third_party"
	ZoneDeploy      Zone = "deploy"
)

// Element kinds.
const (
	KindActor        = "actor"
	KindApplication  = "application"
	KindRoute        = "route"
	KindAgent        = "agent"
	KindMCPServer    = "mcp_server"
	KindMCPClient    = "mcp_client"
	KindModel        = "model"
	KindDataStore    = "data_store"
	KindService      = "external_service"
	KindIngress      = "ingress"
	KindWorkload     = "workload"
	KindImage        = "container_image"
	KindNetworkRule  = "network_rule"
	KindDependencies = "dependencies"
	KindCapability   = "host_capability"
)

// Evidence is one cited piece of what nox holds.
type Evidence struct {
	// Artifact is the scan output the claim comes from (its base name).
	Artifact string `json:"artifact"`
	// Ref locates it: file:line, an inventory entry, or a package.
	Ref string `json:"ref,omitempty"`
	// Statement is the claim, in words. For a finding it is the rule ID and
	// the rule's own message, which is quoted, not authored here.
	Statement string `json:"statement"`
	// RuleID is set when the evidence is a finding.
	RuleID string `json:"rule_id,omitempty"`
	// Severity is the highest severity among the findings grouped here.
	Severity string `json:"severity,omitempty"`
	// Count is how many findings with this rule in this file are grouped.
	Count int `json:"count,omitempty"`
	// Waived marks findings that are baselined, suppressed or VEX-cleared: a
	// person decided to stop looking, which is a decision to cite and not a
	// fix.
	Waived bool `json:"waived,omitempty"`
}

// Element is one thing in the system nox can evidence.
type Element struct {
	// ID is stable across runs and independent of line numbers, so a later run
	// can tell a new element from a moved one.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Zone Zone   `json:"zone"`
	// Location is file:line of the best single place to look.
	Location string `json:"location,omitempty"`
	// Attributes carries grounded detail: the middleware on a route, the
	// capabilities of an agent.
	Attributes map[string]string `json:"attributes,omitempty"`
	// Evidence is why the element exists. Never empty.
	Evidence []Evidence `json:"evidence"`
}

// Flow is a data or control flow between two elements.
type Flow struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
	// Boundary is the trust boundary the flow crosses.
	Boundary string `json:"boundary"`
	// Evidence is what joins the two ends. Never empty.
	Evidence []Evidence `json:"evidence"`
}

// Boundary is a place where data or control crosses from a less-trusted zone
// into a more-trusted one, such as a model's output reaching a shell.
type Boundary struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	From  Zone   `json:"from"`
	To    Zone   `json:"to"`
	// Flows counts the flows that cross it.
	Flows int `json:"flows"`
}

// Cell is the evidence for one element and one STRIDE category.
type Cell struct {
	Category Category `json:"category"`
	Status   Status   `json:"status"`
	// Findings and Waived count active and waived findings behind the cell.
	Findings int `json:"findings"`
	Waived   int `json:"waived"`
	Leads    int `json:"leads"`
	// Evidence is empty exactly when Status is not_evidenced.
	Evidence []Evidence `json:"evidence"`
	// Note is set on a cell with no evidence and says so.
	Note string `json:"note,omitempty"`
}

// Row is the STRIDE assessment of one element.
type Row struct {
	Element string `json:"element"`
	Cells   []Cell `json:"cells"`
	// Other lists findings attached to the element that do not map to a STRIDE
	// category, so they are not lost from the picture.
	Other []Evidence `json:"other_findings,omitempty"`
}

// Question is something the evidence raises that only the team can answer.
type Question struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	// Element is the element the question is about, when there is one.
	Element string `json:"element,omitempty"`
	// Basis is where it comes from.
	Basis Evidence `json:"basis"`
}

// Artifact names one scan output the model relied on. Only the base name is
// kept: an absolute path would make the model differ between machines that hold
// byte-identical evidence.
type Artifact struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// Meta identifies the document. Its shape is the one every nox JSON report
// carries, which is also how a later scan recognises this file as nox's own
// output and does not read it back as source.
type Meta struct {
	SchemaVersion string `json:"schema_version"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	Report        string `json:"report"`
}

// Coverage records which inputs the model was built from, so a later
// comparison can tell "gone" from "not recorded".
type Coverage struct {
	Routes      bool `json:"routes"`
	AIInventory bool `json:"ai_inventory"`
	SBOM        bool `json:"sbom"`
}

// Provenance says what the model was derived from.
type Provenance struct {
	// ScanToolVersion and ScanGeneratedAt come from findings.json, so they
	// describe the scan, not the moment the model was written. The model reads
	// no clock.
	ScanToolVersion  string   `json:"scan_tool_version"`
	ScanGeneratedAt  string   `json:"scan_generated_at"`
	ScanOffline      bool     `json:"scan_offline"`
	ScopesScanned    []string `json:"scopes_scanned"`
	ScopesNotScanned []string `json:"scopes_not_scanned,omitempty"`
	Degradations     int      `json:"degradations"`
	// Commit is the repository revision when the model was generated; the scan
	// may have run at an earlier one.
	Commit    string     `json:"commit,omitempty"`
	Coverage  Coverage   `json:"coverage"`
	Artifacts []Artifact `json:"artifacts"`
}

// Summary counts what the model holds.
type Summary struct {
	Elements   int `json:"elements"`
	Flows      int `json:"flows"`
	Boundaries int `json:"boundaries"`
	// Cells counts the STRIDE cells by status.
	OpenIssues      int `json:"cells_open_issues"`
	LeadsToVerify   int `json:"cells_leads_to_verify"`
	LimitedEvidence int `json:"cells_limited_evidence"`
	NotEvidenced    int `json:"cells_not_evidenced"`
	// UnattributedFindings counts active findings that no modelled element
	// accounts for. They are in findings.json; they are not in this model.
	UnattributedFindings int `json:"unattributed_findings"`
	Questions            int `json:"questions"`
}

// Model is the complete, serialisable result.
type Model struct {
	Meta       Meta       `json:"meta"`
	Notice     string     `json:"notice"`
	Provenance Provenance `json:"provenance"`
	Summary    Summary    `json:"summary"`
	Elements   []Element  `json:"elements"`
	Boundaries []Boundary `json:"boundaries"`
	Flows      []Flow     `json:"flows"`
	STRIDE     []Row      `json:"stride"`
	Questions  []Question `json:"questions"`
	// Limits is what the model cannot see, fixed limits first and then those
	// specific to this run.
	Limits []string `json:"limits"`
	// Changes is set when the model was built against a previous one.
	Changes *Delta `json:"changes,omitempty"`
}
