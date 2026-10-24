// Package feed is the nox CLI's access to the predictive slopsquat blocklist
// that the SLOP analyzer consumes as an additional deterministic signal.
//
// The format itself (the slopsquat-blocklist/v1 schema, its canonical
// encoding and content digest, Ed25519 signing and verification, and lookup)
// lives in github.com/nox-hq/nox-core/slopfeed, shared with the service that
// generates and publishes the feed. This package keeps only what is specific
// to the CLI, each a thin wrapper over slopfeed.Parse:
//
//   - Load reads a feed from a local file.
//   - Bundled returns the feed embedded in the nox binary (data/).
//   - LoadRemote fetches a feed over HTTP(S), verifies digest and signature
//     before use, and caches the verified bytes content-addressed on disk so
//     later scans are offline and deterministic.
//
// Verification always gates use and fails closed: a feed that does not verify
// is never trusted, never cached, and never crashes the scanner.
package feed

import (
	"embed"
	"fmt"
	"os"

	"github.com/nox-hq/nox-core/slopfeed"
)

// Load reads and verifies a feed from a file path.
func Load(path string, opts slopfeed.VerifyOptions) (*slopfeed.Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading feed %s: %w", path, err)
	}
	return slopfeed.Parse(data, opts)
}

//go:embed data/slopsquat-blocklist.v1.json
var bundledFS embed.FS

// Bundled returns the feed shipped in the repo, verified. It lets the feature
// work out of the box for a project that opts in without hosting its own feed.
func Bundled() (*slopfeed.Loaded, error) {
	data, err := bundledFS.ReadFile("data/slopsquat-blocklist.v1.json")
	if err != nil {
		return nil, fmt.Errorf("reading bundled feed: %w", err)
	}
	return slopfeed.Parse(data, slopfeed.VerifyOptions{})
}
