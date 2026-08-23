// Package htmlreport provides an HTML report generator for nox scan findings.
// It produces a standalone single-file HTML report with embedded CSS and
// SVG charts, suitable for opening directly in any browser.
package htmlreport

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"sort"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// Reporter generates standalone HTML reports from scan findings.
type Reporter struct {
	ToolVersion string
}

// NewReporter returns an HTML reporter configured with the given tool version.
func NewReporter(version string) *Reporter {
	return &Reporter{ToolVersion: version}
}

// severityCounts holds per-severity finding counts for the report.
type severityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// findingRow is a template-friendly view of a single finding.
type findingRow struct {
	RuleID      string
	Severity    string
	SevClass    string
	Confidence  string
	FilePath    string
	StartLine   int
	Message     string
	Fingerprint string
}

// reportData is the top-level data passed to the HTML template.
type reportData struct {
	ToolVersion string
	GeneratedAt string
	Counts      severityCounts
	Findings    []findingRow
	SevPercents severityPercents
}

type severityPercents struct {
	Critical float64
	High     float64
	Medium   float64
	Low      float64
	Info     float64
}

// Generate produces a complete, standalone HTML page as bytes.
func (r *Reporter) Generate(fs *findings.FindingSet) ([]byte, error) {
	fs.SortDeterministic()
	items := fs.ActiveFindings()
	if items == nil {
		items = []findings.Finding{}
	}

	counts := severityCounts{Total: len(items)}
	rows := make([]findingRow, len(items))
	for i := range items {
		f := &items[i]
		switch f.Severity {
		case findings.SeverityCritical:
			counts.Critical++
		case findings.SeverityHigh:
			counts.High++
		case findings.SeverityMedium:
			counts.Medium++
		case findings.SeverityLow:
			counts.Low++
		case findings.SeverityInfo:
			counts.Info++
		}
		rows[i] = findingRow{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			SevClass:    sevClass(f.Severity),
			Confidence:  string(f.Confidence),
			FilePath:    f.Location.FilePath,
			StartLine:   f.Location.StartLine,
			Message:     f.Message,
			Fingerprint: f.Fingerprint,
		}
	}

	// Sort by severity rank (critical first) then file path.
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := sevRank(rows[i].Severity), sevRank(rows[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return rows[i].FilePath < rows[j].FilePath
	})

	percents := severityPercents{}
	if counts.Total > 0 {
		percents.Critical = float64(counts.Critical) / float64(counts.Total) * 100
		percents.High = float64(counts.High) / float64(counts.Total) * 100
		percents.Medium = float64(counts.Medium) / float64(counts.Total) * 100
		percents.Low = float64(counts.Low) / float64(counts.Total) * 100
		percents.Info = float64(counts.Info) / float64(counts.Total) * 100
	}

	data := reportData{
		ToolVersion: r.ToolVersion,
		// Use report.GeneratedAt() so the embedded timestamp honors
		// SOURCE_DATE_EPOCH like the JSON and SBOM emitters, keeping the HTML
		// artifact byte-reproducible across runs.
		GeneratedAt: report.GeneratedAt(),
		Counts:      counts,
		Findings:    rows,
		SevPercents: percents,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"pct": func(v float64) string { return fmt.Sprintf("%.1f", v) },
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	return buf.Bytes(), nil
}

// WriteToFile generates the HTML report and writes it to disk.
func (r *Reporter) WriteToFile(fs *findings.FindingSet, path string) error {
	data, err := r.Generate(fs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func sevClass(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return "critical"
	case findings.SeverityHigh:
		return "high"
	case findings.SeverityMedium:
		return "medium"
	case findings.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func sevRank(s string) int {
	// Delegates to the one canonical ranking so the report sorts severities the
	// same way the policy gate compares them.
	return findings.SeverityRank(findings.Severity(s))
}
