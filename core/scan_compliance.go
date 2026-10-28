package core

import (
	"fmt"

	"github.com/nox-hq/nox/core/compliance/iso27001"
	"github.com/nox-hq/nox/core/report/sbom"
)

// ISO27001Input packages a completed scan as the evidence an ISO/IEC 27001
// assessment is derived from, for a surface (the MCP server) that holds a scan
// in memory rather than as files on disk.
//
// It serialises through the same reporters `nox scan` writes with, so the
// digests it records are those of the files the scan would have produced, and
// the assessment cannot disagree with one read back from disk. The SBOM is
// omitted when the deps scope did not run: an SBOM from a scan that read no
// lockfile would claim the project has no dependencies.
func (r *ScanResult) ISO27001Input(version string) (iso27001.Input, error) {
	in := iso27001.Input{NoxVersion: version}

	data, err := r.JSONReporter(version).Generate(r.Findings)
	if err != nil {
		return in, fmt.Errorf("serialising findings: %w", err)
	}
	rep, art, err := iso27001.ParseFindings("findings.json", data)
	if err != nil {
		return in, err
	}
	in.Report = rep
	in.Artifacts = append(in.Artifacts, art)

	if r.Scope.Has(ScopeDeps) {
		raw, err := sbom.NewCycloneDXReporter(version).WithAIInventory(r.AIInventory).Generate(r.Inventory)
		if err != nil {
			return in, fmt.Errorf("serialising SBOM: %w", err)
		}
		s, sa, err := iso27001.ParseSBOM("sbom.cdx.json", raw)
		if err != nil {
			return in, err
		}
		in.SBOM = s
		in.Artifacts = append(in.Artifacts, sa)
	}

	if r.AIInventory != nil {
		raw, err := r.AIInventory.JSON()
		if err != nil {
			return in, fmt.Errorf("serialising AI inventory: %w", err)
		}
		a, aa, err := iso27001.ParseAIInventory("ai.inventory.json", raw)
		if err != nil {
			return in, err
		}
		in.AI = a
		in.Artifacts = append(in.Artifacts, aa)
	}
	return in, nil
}
