package core

import (
	"context"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/depimports"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/intel"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/source"
	"github.com/nox-hq/nox/core/taint/engine"
)

// maxInventoryReadBytes bounds one source read while deriving an inventory. A
// file larger than this is a bundle or generated output, and what it imports
// or calls says nothing about the service's own code.
const maxInventoryReadBytes = 1 << 20

// DeriveServiceInventory scans target and describes it as one service for the
// intelligence service's blast-radius assessment.
//
// The packages come from the scan. Two further facts are read from the
// service's own source, with the scan's own discovery rules (scan.exclude,
// scan.include, .gitignore): whether it imports each package, and which sinks
// it calls, which is what its capabilities are derived from. Test code is left
// out of both — a test helper that shells out is not a capability of the
// deployed service, and a test-only import is not a dependency it uses.
//
// The scan runs offline whatever opts says. An inventory needs the packages,
// not their advisories, and a lookup would send the dependency list to a
// vulnerability service in order to build a description the operator has not
// yet decided to send anywhere.
func DeriveServiceInventory(ctx context.Context, target string, inv intel.InventoryOptions, opts ScanOptions) (*intel.ServiceInventory, error) {
	opts.Offline = true
	result, err := RunScanContext(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadScanConfig(target)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	artifacts, err := discoverArtifacts(target, cfg, opts)
	if err != nil {
		return nil, err
	}

	ix := depimports.New()
	eng := engine.NewStructuralEngine(nil)
	var sites []intel.SinkSite
	for i := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := &artifacts[i]
		if art.Type != discovery.Source || source.IsTestPath(art.Path) {
			continue
		}
		info, err := os.Stat(art.AbsPath)
		if err != nil || info.Size() > maxInventoryReadBytes {
			continue
		}
		content, err := os.ReadFile(art.AbsPath) // #nosec G304 -- path came from the scan's own discovery walk
		if err != nil {
			continue
		}
		ix.Add(art.Path, content)
		lang := lexctx.LangFromPath(art.Path)
		if lang == lexctx.LangUnknown {
			continue
		}
		for _, s := range eng.SinkSites(engine.ExtractUnits(art.Path, lang, content)) {
			sites = append(sites, intel.SinkSite{Class: string(s.Class), Call: s.Call, File: s.FilePath, Line: s.Line})
		}
	}

	imports := func(ecosystem, name string) bool {
		return depimports.Supported(ecosystem) && ix.Known(ecosystem) && ix.Imports(ecosystem, name)
	}
	var pkgs []intel.Package
	if result.Inventory != nil {
		for _, p := range result.Inventory.Packages() {
			pkgs = append(pkgs, intel.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
		}
	}
	return intel.BuildServiceInventory(pkgs, imports, sites, inv)
}
