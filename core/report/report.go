// Package report provides finding serialization to various output formats.
// The primary implementation is JSONReporter which produces a deterministic
// JSON report suitable for CI pipelines, dashboards, and downstream tooling.
package report

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

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
		Findings: f,
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
