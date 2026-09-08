// Package report provides finding serialization to various output formats.
// The primary implementation is JSONReporter which produces a deterministic
// JSON report suitable for CI pipelines, dashboards, and downstream tooling.
package report

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
)

// GeneratedAt returns the report timestamp. It honors SOURCE_DATE_EPOCH (the
// reproducible-builds standard: a Unix timestamp in seconds) so a scan can
// produce byte-identical output across runs — the proof-of-determinism a
// reviewer or CI cache can rely on. Without it, the current time is used.
// Shared by the JSON and SBOM reporters so every timestamped artifact honors
// the same reproducibility switch.
func GeneratedAt() string {
	if e := os.Getenv("SOURCE_DATE_EPOCH"); e != "" {
		if secs, err := strconv.ParseInt(e, 10, 64); err == nil {
			return time.Unix(secs, 0).UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// Reporter defines the contract for serializing a FindingSet into a byte
// representation. Each output format (JSON, SARIF, SBOM, etc.) implements
// this interface.
type Reporter interface {
	Generate(fs *findings.FindingSet) ([]byte, error)
}

// Meta contains metadata about the report itself, including schema
// version, generation timestamp, and tool identification.
type Meta struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	// Offline records whether the scan ran under the zero-network guarantee
	// (`nox scan --offline`): no OSV lookups, no API, no token, no telemetry.
	// It is the proof-of-offline attestation a reviewer can read straight from
	// the artifact — "this report was produced without the scanner touching the
	// network" — backed by the enforced egress test, not just a claim.
	Offline bool `json:"offline"`
	// SASTLanguages records the resolved per-language SAST depth applied to the
	// scan (language name → deep|standard|off). It makes the depth strategy
	// auditable straight from the artifact: a reviewer can see that, say,
	// `go` was scanned at standard and `rust` was turned off, without
	// re-deriving defaults from config. Omitted from JSON when empty (a scan
	// run without a profile, e.g. history scans).
	SASTLanguages map[string]string `json:"sast_languages,omitempty"`
	// Degradations records checks that did not complete — a failed OSV lookup,
	// a required plugin that never ran, an unparsed lockfile.
	//
	// It belongs in the artifact and not only on stderr, because the consumers
	// that most need it never see stderr: a CI job reading findings.json, a
	// dashboard, an MCP client. Without it, an empty findings list is
	// indistinguishable from a scan that never looked. Omitted when the scan
	// was complete.
	Degradations []Degradation `json:"degradations,omitempty"`
	// Capabilities records which analysis questions this scan could ask, and
	// how many of them it actually answered.
	//
	// Degradations report what BROKE. This reports what was never possible in
	// the first place, which no failure will ever announce: an installation
	// that provides no call graph produces a scan with no call-graph errors
	// and no call-graph answers, and the artifact reads exactly like one from
	// an installation that has it and found nothing. That is the state
	// core/capability exists to make visible, and until now it died at the
	// artifact boundary — held on ScanResult, serialized nowhere, so the only
	// consumers who could see it were the ones already inside the process.
	//
	// Omitted when the reporter was given no coverage, which keeps a report
	// built without a scan (a filtered re-render, a fixture) from claiming a
	// capability matrix it never had.
	Capabilities []CapabilityCoverage `json:"capabilities,omitempty"`
	// CompetenceProfiles are the distinct sets of unanswered questions this
	// scan holds. Each finding names the one it belongs to in its
	// CompetenceProfile field.
	//
	// Capabilities above is the run-level summary and cannot answer the
	// question a triager actually asks, which is about ONE finding: was
	// reachability evaluated for THIS one? A run-level "reachability answered 4
	// subjects" leaves every reader of the other forty-nine to guess, and the
	// comfortable guess is the wrong one.
	//
	// Omitted when the scan recorded no coverage. Absent does not mean full
	// competence.
	CompetenceProfiles []capability.Profile `json:"competence_profiles,omitempty"`
	// StageAccounting records what each rule family produced and what became of
	// it: candidates in, promoted, refuted on evidence, withheld by
	// configuration.
	//
	// It answers a question a finding count cannot. A family that generates a
	// thousand candidates and refutes none is doing no refinement; one that
	// refutes nine in ten is doing most of its work after the match. Both
	// produce findings, and only this tells them apart.
	//
	// Present only when the scan recorded reasoning, because a refuted
	// candidate never becomes a finding and the ledger is the only place it
	// exists. Deliberately carries no timing: this artifact is byte-identical
	// across runs by contract and a duration is not.
	StageAccounting []StageCount `json:"stage_accounting,omitempty"`
}

// StageCount is one rule family's account, as recorded in the artifact. It
// mirrors core.StageCount, which owns the derivation.
type StageCount struct {
	Family     string `json:"family"`
	Candidates int    `json:"candidates"`
	Promoted   int    `json:"promoted"`
	Refuted    int    `json:"refuted"`
	Withheld   int    `json:"withheld"`
	Unresolved int    `json:"unresolved"`
}

// CapabilityCoverage is one analysis capability's standing in a scan: whether
// this installation can answer the question at all, and how often it did.
//
// The two halves are separate on purpose and must not be collapsed. Provided
// is a property of the INSTALLATION — permanent, and knowable without running
// anything. Answered is a property of this RUN, and the two come apart exactly
// when something fails at runtime: reachability is provided by every nox build,
// and on a scan whose advisory source was unreachable it establishes nothing.
// A consumer that reads only Provided sees a capability nox has; one that reads
// only Answered cannot tell "nothing to say" from "nothing to say it with".
type CapabilityCoverage struct {
	Capability string `json:"capability"`
	// Provided reports whether any implementation on this installation offers
	// the capability. False is a limit nox can state plainly — not a failure,
	// and never a clearance.
	Provided bool `json:"provided"`
	// Providers names the implementations, sorted. Empty when none.
	Providers []string `json:"providers,omitempty"`
	// Answered counts the subjects this capability reached a conclusion about,
	// positive or negative. Negative counts: "the build links no package under
	// crypto/md5" is a real answer, and the strongest a static scan reaches.
	Answered int `json:"answered"`
	// Inconclusive counts the subjects it was asked about and could not
	// determine — evaluated-and-unknown, or timed out. These are the ones that
	// must never be added to Answered: they mean the question was put and came
	// back empty, and counting them as coverage rebuilds the false all-clear
	// one layer up.
	Inconclusive int `json:"inconclusive"`
}

// Degradation is a single incomplete check, as recorded in the artifact.
type Degradation struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	// Impact states what may be missing from the results, in the operator's
	// terms. It is the field that answers "should I trust this report?".
	Impact string `json:"impact"`
}

// JSONReport is the top-level structure serialized to JSON. It pairs report
// metadata with the ordered list of findings.
type JSONReport struct {
	Meta     Meta               `json:"meta"`
	Findings []findings.Finding `json:"findings"`
	// Enrichments are plugin annotations keyed to a finding's fingerprint.
	// Omitted when empty so scans without post-scan plugins are unchanged.
	Enrichments []findings.Enrichment `json:"enrichments,omitempty"`
}

// ActiveFindings returns the report's findings that are still active — not
// baselined, suppressed, or VEX-cleared. A file-driven consumer (the vex, badge,
// annotate, and attack commands, plus MCP/LSP) needs the same "which findings
// surface" rule the scan path gets from FindingSet.ActiveFindings, so it lives
// on the loaded report too rather than being re-filtered by hand per caller.
func (r JSONReport) ActiveFindings() []findings.Finding {
	out := make([]findings.Finding, 0, len(r.Findings))
	for i := range r.Findings {
		if r.Findings[i].Status.IsActive() {
			out = append(out, r.Findings[i])
		}
	}
	return out
}

// LoadFindingsFile reads a findings.json written by `nox scan` and returns its
// findings.
//
// It is the ONE loader for that artifact. Every command that consumed a prior
// scan used to unmarshal it inline, and one of them (vex init) had drifted to
// unmarshalling into a []findings.Finding — but `nox scan` writes a JSON OBJECT
// ({meta, findings, enrichments}), so that parse failed against every real
// artifact. A single loader against the real shape ends that whole class of
// drift.
func LoadFindingsFile(path string) ([]findings.Finding, error) {
	rep, err := LoadFindingsFileReport(path)
	if err != nil {
		return nil, err
	}
	return rep.Findings, nil
}

// LoadFindingsFileReport reads a findings.json and returns the whole report, for
// a caller that needs more than the raw findings — e.g. ActiveFindings().
func LoadFindingsFileReport(path string) (JSONReport, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // caller-supplied scan artifact
	if err != nil {
		return JSONReport{}, err
	}
	var rep JSONReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return JSONReport{}, err
	}
	return rep, nil
}

// DegradationsFrom converts scan degradations into their report form.
//
// It lives here, and every reporter construction site uses it, because the
// conversion being one function is what stops a surface from quietly omitting
// degradations. The MCP server did exactly that: three of its reporter sites
// never set the field, so an agent asking for the findings report got one that
// said nothing about the checks that had not run — the single consumer least
// able to notice, since it has no stderr to read.
func DegradationsFrom(ds []degrade.Degradation) []Degradation {
	if len(ds) == 0 {
		return nil
	}
	out := make([]Degradation, 0, len(ds))
	for _, d := range ds {
		out = append(out, Degradation{
			Kind:   string(d.Kind),
			Detail: d.Detail,
			Impact: d.Impact,
		})
	}
	return out
}

// CapabilitiesFrom converts a scan's capability registry and coverage into
// their report form: one row per defined capability, cheapest first.
//
// Every capability is emitted, including the ones nothing provides and the ones
// that answered nothing. That is the whole point — a matrix that lists only
// what worked is a matrix a reader will mistake for the complete set of
// questions. Nine rows, always, is what lets a consumer see that two of them
// were never askable.
//
// A nil registry and a nil coverage are both usable: the result is every
// capability marked unprovided with nothing answered, which is the honest
// description of an installation that declared nothing.
func CapabilitiesFrom(reg *capability.Registry, cov *capability.Coverage) []CapabilityCoverage {
	all := capability.All()
	out := make([]CapabilityCoverage, 0, len(all))
	for _, c := range all {
		answered, inconclusive := cov.Answered(c)
		out = append(out, CapabilityCoverage{
			Capability:   string(c),
			Provided:     reg.Provided(c),
			Providers:    reg.ProvidedBy(c),
			Answered:     answered,
			Inconclusive: inconclusive,
		})
	}
	return out
}

// JSONReporter produces deterministic JSON output from a FindingSet.
type JSONReporter struct {
	ToolVersion string
	// Offline is recorded in the report Meta as the proof-of-offline
	// attestation. Set it to the scan's `--offline` state before Generate.
	Offline bool
	// Prioritize orders findings by priority (severity, then reachability, then
	// confidence) instead of the canonical deterministic order — the most
	// actionable findings first, likely-false-positive unreachable vulns last.
	Prioritize bool
	// SASTLanguages is the resolved per-language SAST depth for this scan,
	// recorded verbatim in the report Meta. Set it from ScanResult.SASTProfile
	// before Generate to make the depth strategy auditable in the artifact.
	SASTLanguages map[string]string
	// Degradations are the scan's incomplete checks. Set from
	// ScanResult.Degradations before Generate so a consumer reading only the
	// artifact can tell a clean scan from one that could not run.
	Degradations []Degradation
	// Enrichments are plugin annotations attached to findings by fingerprint.
	// Set from ScanResult.Enrichments before Generate. Without this a post-scan
	// plugin's output never reaches the artifact, which makes a plugin that
	// annotates rather than detects indistinguishable from one that did not run.
	Enrichments []findings.Enrichment
	// Capabilities is the analysis capability matrix for this scan. Set it with
	// CapabilitiesFrom(result.Capabilities, result.Coverage) — or, better, let
	// core.ScanResult.JSONReporter set it, so no surface has to remember.
	Capabilities []CapabilityCoverage
	// CompetenceProfiles is the per-claim half of the same picture. Set from
	// ScanResult.CompetenceProfiles, and likewise best left to the constructor.
	CompetenceProfiles []capability.Profile
	// StageAccounting is what each rule family produced and what became of it.
	// Set from ScanResult.Stages, and likewise best left to the constructor.
	StageAccounting []StageCount
}

// NewJSONReporter returns a JSONReporter configured with the given tool version
// string. The version is embedded in the report metadata.
func NewJSONReporter(version string) *JSONReporter {
	return &JSONReporter{ToolVersion: version}
}

// Generate sorts the finding set deterministically, then serializes it to
// pretty-printed JSON with 2-space indentation. The output is stable across
// runs given the same input findings (aside from the GeneratedAt timestamp).
func (r *JSONReporter) Generate(fs *findings.FindingSet) ([]byte, error) {
	if r.Prioritize {
		fs.SortByPriority()
	} else {
		fs.SortDeterministic()
	}

	f := fs.Findings()

	// Guarantee a non-nil slice so JSON output renders "findings": [] rather
	// than "findings": null for an empty finding set.
	if f == nil {
		f = []findings.Finding{}
	}

	report := JSONReport{
		Meta: Meta{
			SchemaVersion: "1.0.0",
			GeneratedAt:   GeneratedAt(),
			ToolName:      "nox",
			ToolVersion:   r.ToolVersion,
			Offline:       r.Offline,
			SASTLanguages: r.SASTLanguages,
			Degradations:  r.Degradations,
			Capabilities:  r.Capabilities,

			CompetenceProfiles: r.CompetenceProfiles,
			StageAccounting:    r.StageAccounting,
		},
		Findings:    f,
		Enrichments: r.Enrichments,
	}

	return json.MarshalIndent(report, "", "  ")
}

// WriteToFile generates the JSON report and writes it to the specified path
// with 0644 permissions. Parent directories must already exist.
func (r *JSONReporter) WriteToFile(fs *findings.FindingSet, path string) error {
	data, err := r.Generate(fs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
