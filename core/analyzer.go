package core

import (
	"context"

	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// FindingAnalyzer is the common contract for analyzers that consume discovered
// artifacts and produce a set of findings. The secrets, data, and IaC analyzers
// satisfy it directly.
//
// The AI and dependency analyzers intentionally do NOT implement this
// interface: each additionally produces an inventory (an AI component inventory
// and a package inventory, respectively), so they return richer tuples. Forcing
// them behind a lowest-common-denominator interface would hide that output, so
// the orchestrator (RunScanContext) calls them by their concrete types.
type FindingAnalyzer interface {
	ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error)
}

// Compile-time checks that the finding-only analyzers satisfy the interface.
var (
	_ FindingAnalyzer = (*secrets.Analyzer)(nil)
	_ FindingAnalyzer = (*data.Analyzer)(nil)
	_ FindingAnalyzer = (*iac.Analyzer)(nil)
)
