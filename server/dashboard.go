package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/badge"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

//go:embed dashboard/dashboard.html
var dashboardFS embed.FS

// dashboardData is the JSON structure injected into the HTML template.
type dashboardData struct {
	Version      string             `json:"version"`
	GeneratedAt  string             `json:"generated_at"`
	Findings     []findings.Finding `json:"findings"`
	Suppressed   int                `json:"suppressed"`
	Packages     []dashboardPackage `json:"packages"`
	AIComponents []dashboardAIComp  `json:"ai_components"`
	Baseline     *dashboardBaseline `json:"baseline,omitempty"`
}

type dashboardPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type dashboardAIComp struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type dashboardBaseline struct {
	Total   int `json:"total"`
	Expired int `json:"expired"`
}

// GenerateDashboardHTML renders the dashboard HTML with scan data injected.
func GenerateDashboardHTML(result *nox.ScanResult, version, basePath string) (string, error) {
	tmplBytes, err := dashboardFS.ReadFile("dashboard/dashboard.html")
	if err != nil {
		return "", fmt.Errorf("reading dashboard template: %w", err)
	}

	data := buildDashboardData(result, version, basePath)

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshalling dashboard data: %w", err)
	}

	// Inject data by replacing the __NOX_DATA__ placeholder block.
	html := strings.Replace(
		string(tmplBytes),
		"// When served via MCP resource or CLI, __NOX_DATA__ is replaced with actual scan data.\nconst DATA = typeof __NOX_DATA__ !== 'undefined' ? __NOX_DATA__ : {};",
		"const DATA = "+string(dataJSON)+";",
		1,
	)

	return html, nil
}

func buildDashboardData(result *nox.ScanResult, version, basePath string) dashboardData {
	active := result.Findings.ActiveFindings()
	total := len(result.Findings.Findings())

	data := dashboardData{
		Version:    version,
		Findings:   active,
		Suppressed: total - len(active),
	}

	// Generate timestamp from badge score (reuses badge logic).
	counts := badge.CountBySeverity(active)
	_ = counts // counts used implicitly by findings

	// Packages
	for _, p := range result.Inventory.Packages() {
		data.Packages = append(data.Packages, dashboardPackage{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
		})
	}

	// AI components
	for _, c := range result.AIInventory.Components {
		data.AIComponents = append(data.AIComponents, dashboardAIComp{
			Type: c.Type,
			Name: c.Name,
		})
	}

	// Baseline (best-effort)
	bl, err := baseline.Load(baseline.DefaultPath(basePath))
	if err == nil && bl.Len() > 0 {
		data.Baseline = &dashboardBaseline{
			Total:   bl.Len(),
			Expired: bl.ExpiredCount(),
		}
	}

	return data
}
