// Package dashboard renders the interactive HTML security dashboard from a scan
// result.
//
// It lives in core because a dashboard is a report — a projection of scan
// output — and more than one entry point produces it: the `nox dashboard` CLI
// command and three MCP surfaces (the dashboard tool and two resources). It used
// to live in server/, which forced the CLI to import the MCP server package to
// render a report — an adapter depending on another adapter. Moving it here
// makes the dashboard a domain artifact both adapters call, and removes that
// cross-adapter edge.
package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

//go:embed dashboard.html
var dashboardFS embed.FS

// data is the JSON structure injected into the HTML template.
type data struct {
	Version      string             `json:"version"`
	GeneratedAt  string             `json:"generated_at"`
	Findings     []findings.Finding `json:"findings"`
	Suppressed   int                `json:"suppressed"`
	Packages     []pkg              `json:"packages"`
	AIComponents []aiComp           `json:"ai_components"`
	Baseline     *baselineSummary   `json:"baseline,omitempty"`
}

type pkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type aiComp struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type baselineSummary struct {
	Total   int `json:"total"`
	Expired int `json:"expired"`
}

// GenerateHTML renders the dashboard HTML with scan data injected.
func GenerateHTML(result *nox.ScanResult, version, basePath string) (string, error) {
	tmplBytes, err := dashboardFS.ReadFile("dashboard.html")
	if err != nil {
		return "", fmt.Errorf("reading dashboard template: %w", err)
	}

	dataJSON, err := json.Marshal(buildData(result, version, basePath))
	if err != nil {
		return "", fmt.Errorf("marshalling dashboard data: %w", err)
	}

	// Normalize line endings (CRLF -> LF) for cross-platform consistency.
	tmpl := strings.ReplaceAll(string(tmplBytes), "\r\n", "\n")

	// Inject data by replacing the __NOX_DATA__ placeholder block.
	html := strings.Replace(
		tmpl,
		"// When served via MCP resource or CLI, __NOX_DATA__ is replaced with actual scan data.\nconst DATA = typeof __NOX_DATA__ !== 'undefined' ? __NOX_DATA__ : {};",
		"const DATA = "+string(dataJSON)+";",
		1,
	)
	return html, nil
}

// buildData projects a scan result into the injectable dashboard payload.
func buildData(result *nox.ScanResult, version, basePath string) data {
	active := result.Findings.ActiveFindings()
	total := len(result.Findings.Findings())

	d := data{
		Version:    version,
		Findings:   active,
		Suppressed: total - len(active),
	}
	for _, p := range result.Inventory.Packages() {
		d.Packages = append(d.Packages, pkg{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem})
	}
	for _, c := range result.AIInventory.Components {
		d.AIComponents = append(d.AIComponents, aiComp{Type: c.Type, Name: c.Name})
	}
	// Baseline is best-effort: a project without one still renders.
	if bl, err := baseline.Load(baseline.DefaultPath(basePath)); err == nil && bl.Len() > 0 {
		st := bl.Status()
		d.Baseline = &baselineSummary{Total: st.Total, Expired: st.Expired}
	}
	return d
}
