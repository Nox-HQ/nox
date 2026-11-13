package core

import "github.com/nox-hq/nox/core/report/sbom"

// CycloneDX is the CycloneDX reporter for this scan: the AI inventory, so the
// ML-BOM carries the models the scan detected, and the findings, so each
// dependency vulnerability nox decided is not impacting carries its VEX
// analysis. Every CycloneDX surface (the CLI, the MCP server, compliance and
// threat-model evidence) is built here so none of them drops either.
func (r *ScanResult) CycloneDX(version string) *sbom.CycloneDXReporter {
	rep := sbom.NewCycloneDXReporter(version).WithAIInventory(r.AIInventory)
	if r.Findings != nil {
		rep = rep.WithFindings(r.Findings.Findings())
	}
	return rep
}
