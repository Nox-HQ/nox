package core

import (
	"fmt"

	"github.com/nox-hq/nox/core/report/sbom"
	"github.com/nox-hq/nox/core/threatmodel"
)

// ThreatModelInput packages a completed scan as the evidence a threat model is
// derived from, for a surface (the MCP server) that holds a scan in memory
// rather than as files on disk.
//
// It serialises through the same reporters `nox scan` writes with, so the
// digests it records are those of the files the scan would have produced and
// the model cannot disagree with one read back from disk. The SBOM is omitted
// when the deps scope did not run: an SBOM from a scan that read no lockfile
// would claim the project has no dependencies.
func (r *ScanResult) ThreatModelInput(version string) (threatmodel.Input, error) {
	in := threatmodel.Input{NoxVersion: version}

	data, err := r.JSONReporter(version).Generate(r.Findings)
	if err != nil {
		return in, fmt.Errorf("serialising findings: %w", err)
	}
	rep, art, err := threatmodel.ParseFindings("findings.json", data)
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
		s, sa, err := threatmodel.ParseSBOM("sbom.cdx.json", raw)
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
		inv, ia, err := threatmodel.ParseInventory("ai.inventory.json", raw)
		if err != nil {
			return in, err
		}
		in.Inventory = inv
		in.Artifacts = append(in.Artifacts, ia)
	}
	return in, nil
}
