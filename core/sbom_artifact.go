package core

import (
	"context"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/artifact"
	"github.com/nox-hq/nox/core/report/sbom"
)

// ArtifactSBOM is the SPDX SBOM of one built artifact, such as a release
// archive: what it contains, read by nox itself, with the artifact as the
// document's subject (named, with its SHA-256).
//
// The scan is offline and dependency-only. An SBOM records what shipped, so it
// does not depend on when it was made or on any service: the same artifact
// yields the same document. Go executables inside are read from the build info
// they embed (core/analyzers/deps/gobinary.go).
func ArtifactSBOM(ctx context.Context, path, toolVersion string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "nox-artifact-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }() // scratch extraction only

	a, err := artifact.Open(path, dir)
	if err != nil {
		return nil, err
	}
	scopes, err := ResolveScopes([]string{string(ScopeDeps)}, nil)
	if err != nil {
		return nil, err
	}
	res, err := RunScanContext(ctx, a.Dir, ScanOptions{
		ToolVersion:        toolVersion,
		Scopes:             scopes,
		Offline:            true,
		DisableOSV:         true,
		NoRespectGitignore: true,
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", a.Name, err)
	}
	return sbom.NewSPDXReporter(toolVersion).WithSubject(a.Name, a.SHA256).Generate(res.Inventory)
}
