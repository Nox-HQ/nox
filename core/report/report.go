// Package report provides finding serialization to various output formats.
// The primary implementation is JSONReporter which produces a deterministic
// JSON report suitable for CI pipelines, dashboards, and downstream tooling.
package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

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
	fs.SortDeterministic()

	f := fs.Findings()

	// Guarantee a non-nil slice so JSON output renders "findings": [] rather
	// than "findings": null for an empty finding set.
	if f == nil {
		f = []findings.Finding{}
	}

	report := JSONReport{
		Meta: Meta{
			SchemaVersion: "1.0.0",
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			ToolName:      "nox",
			ToolVersion:   r.ToolVersion,
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
