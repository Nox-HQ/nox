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
