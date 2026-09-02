package deps

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/depimports"
	"github.com/nox-hq/nox/core/reach"
)

// goListTimeout bounds the toolchain call used to enumerate imported packages.
// Reachability is an enrichment, never a blocker: if the toolchain is slow,
// absent, or offline, the scan proceeds with reachability simply unknown.
const goListTimeout = 60 * time.Second

// goAffectedImports returns the import paths an advisory names as affected.
//
// OSV scopes Go advisories to specific packages within a module. GO-2026-5932,
// for instance, applies only to golang.org/x/crypto/openpgp and its
// subpackages — a module that links x/crypto/chacha20 is not exposed by it.
// Matching at module granularity alone therefore overstates exposure.
func goAffectedImports(vuln *osvVuln, module string) []string {
	var out []string
	for _, aff := range vuln.Affected {
		if !strings.EqualFold(aff.Package.Name, module) {
			continue
		}
		for _, im := range aff.EcosystemSpecific.Imports {
			if im.Path != "" {
				out = append(out, im.Path)
			}
		}
	}
	return out
}

// goImportedPackages enumerates every package the module in dir links,
// transitively, via `go list -deps ./...`.
//
// This deliberately uses the toolchain rather than parsing imports out of
// source: a vulnerable package is frequently reached *through* a dependency
// rather than imported by the repository directly, and static parsing of the
// repo's own files cannot see that. Getting it wrong in that direction would
// silently hide real vulnerabilities, so when the toolchain cannot answer,
// this reports ok=false and callers keep the finding.
func goImportedPackages(ctx context.Context, dir string) (map[string]struct{}, bool) {
	// A directory with no go.mod is not a module, and `go list -deps -e ./...`
	// does NOT say so: it exits 0 and prints the standard library's dependency
	// closure. Ninety-one packages, none of them the caller's, and no error.
	//
	// Without this check the result is a confident wrong answer rather than an
	// absent one — a large non-empty set with ok=true, in which any advisory's
	// import path is missing, so every Go advisory would be answered
	// "deterministically unreachable" for a directory nox never managed to
	// enumerate. That is precisely the Gate B failure: a blind spot reported as
	// an all-clear.
	//
	// The only caller today passes a directory where a go.mod was already
	// found, so this was not reachable in production. It was reachable from the
	// documented contract — "when the toolchain cannot answer, this reports
	// ok=false" — which was false as written, and would have become reachable
	// the first time a second caller believed it. Found by
	// testdata/reachability-suite on its first run.
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		slog.DebugContext(ctx, "no go.mod; the linked package set is unknown rather than empty",
			"dir", dir)
		return nil, false
	}

	ctx, cancel := context.WithTimeout(ctx, goListTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-e", "-f", "{{.ImportPath}}", "./...")
	cmd.Dir = dir
	// Never mutate the module files of the repository under scan.
	cmd.Env = append(cmd.Environ(), "GOFLAGS=-mod=readonly")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		slog.DebugContext(ctx, "go list failed; dependency findings will not be scoped by import path",
			"dir", dir, "error", err, "stderr", strings.TrimSpace(stderr.String()))
		return nil, false
	}

	pkgs := make(map[string]struct{})
	scanner := newLineScanner(&stdout)
	for scanner.Scan() {
		p := strings.TrimSpace(scanner.Text())
		// With -e, `go list` outside a module echoes the unresolved pattern
		// itself (e.g. "./...") and still exits 0. Those are not packages, and
		// accepting them would make an empty directory look like a resolved
		// build — turning "unknown" into a false "not linked".
		if p == "" || strings.HasPrefix(p, "./") || strings.Contains(p, "...") {
			continue
		}
		pkgs[p] = struct{}{}
	}
	if len(pkgs) == 0 {
		return nil, false
	}
	return pkgs, true
}

// goVulnReachable reports whether an advisory's affected packages are actually
// linked, along with whether that could be determined at all.
//
// It answers false only on positive evidence: the advisory named its affected
// import paths, the linked package set is known, and none of those paths appear
// in it. Anything less — no import metadata, no package set — returns
// determined=false so the caller leaves the finding untouched.
func goVulnReachable(affectedImports []string, linked map[string]struct{}, linkedKnown bool) (reachable, determined bool) {
	if len(affectedImports) == 0 || !linkedKnown {
		return true, false
	}
	for _, imp := range affectedImports {
		if _, ok := linked[imp]; ok {
			return true, true
		}
		// A vulnerable package's subpackages are covered by the same advisory.
		for pkg := range linked {
			if strings.HasPrefix(pkg, imp+"/") {
				return true, true
			}
		}
	}
	return false, true
}

// goSymbolReferenced answers whether the advisory's affected import is in the
// build's linked package set, and says so at the level it actually establishes.
//
// That level is reach.SymbolReferenced. `go list -deps` is a linker-level
// answer: it knows what the build links, not what calls what, so it cannot
// speak to CallPathExists or anything above it. The previous form of this
// answer was a bare `reachable` boolean, which read as the stronger claim and
// was counted as the reachability capability.
//
// The scope carries the asymmetry. When the linked set is unknown — no go.mod,
// a toolchain failure — the scope is incomplete and reach.Refute refuses to
// build a negative from it, returning Undetermined instead. When the set IS
// known, the search over it is exhaustive by construction: `go list -deps`
// enumerates the whole closure, so "no affected import is linked" is a
// universal claim this analysis can actually make.
func goSymbolReferenced(affectedImports []string, linked map[string]struct{}, linkedKnown bool) (reach.Result, bool) {
	subject := evidence.Subject{Kind: evidence.SubjectPackage, ID: strings.Join(affectedImports, ",")}
	scope := reach.Scope{
		Analysis:   "go list -deps",
		Capability: capability.SymbolResolution,
		BuildID:    "go build closure",
	}
	if len(affectedImports) == 0 {
		// The advisory named no import paths, so there is nothing to look for.
		scope.Limitations = append(scope.Limitations, reach.UnsupportedFramework)
		return reach.Undeterminable(subject, reach.SymbolReferenced, scope), false
	}
	if !linkedKnown {
		scope.Limitations = append(scope.Limitations, reach.BudgetExhausted)
		return reach.Undeterminable(subject, reach.SymbolReferenced, scope), false
	}

	for _, imp := range affectedImports {
		if _, ok := linked[imp]; ok {
			r, _ := reach.Establish(subject, reach.SymbolReferenced, scope, []string{imp})
			return r, true
		}
		for pkg := range linked {
			if strings.HasPrefix(pkg, imp+"/") {
				r, _ := reach.Establish(subject, reach.SymbolReferenced, scope, []string{pkg})
				return r, true
			}
		}
	}
	r, ok := reach.Refute(subject, reach.SymbolReferenced, scope)
	return r, ok
}

// maxImportScanBytes bounds a single file read when indexing imports. A source
// file larger than this is a bundle or a generated blob, and its import list is
// not evidence about what this project uses.
const maxImportScanBytes = 1 << 20

// sourceImports lazily indexes the imports of a scan's source files.
//
// Lazily, because most scans have no vulnerable dependency in an ecosystem this
// can answer for, and the index costs a read of every source file. Nothing is
// read until the first finding actually asks.
type sourceImports struct {
	paths []string
	index *depimports.Index
}

// get builds the index on first use and returns it.
func (s *sourceImports) get() *depimports.Index {
	if s.index != nil {
		return s.index
	}
	ix := depimports.New()
	for _, p := range s.paths {
		info, err := os.Stat(p)
		if err != nil || info.Size() > maxImportScanBytes {
			continue
		}
		content, err := os.ReadFile(p) // #nosec G304 -- path came from the scan's own discovery walk
		if err != nil {
			continue
		}
		ix.Add(p, content)
	}
	s.index = ix
	return ix
}

// importApplicability answers the SymbolUsed rung for the ecosystems whose
// import statement names the distribution.
//
// It ONLY CLIMBS. goImportedPackages deliberately asks the toolchain rather
// than parsing the repository's own imports, because a vulnerable package is
// usually reached THROUGH a dependency and static parsing cannot see that —
// getting it wrong in that direction would hide real vulnerabilities. That
// reasoning is why this never returns a refutation: a direct import is positive
// evidence that the package is used, and its absence is not evidence of
// anything. Every miss degrades to the undetermined verdict callers already got.
func importApplicability(pkg Package, reached applicability.Rung, src *sourceImports) (applicability.Verdict, bool) {
	if !depimports.Supported(pkg.Ecosystem) {
		return applicability.Verdict{}, false
	}
	ix := src.get()
	if !ix.Known(pkg.Ecosystem) {
		// No source of that language was read, so the question was never put.
		return applicability.Verdict{}, false
	}
	if !ix.Imports(pkg.Ecosystem, pkg.Name) {
		return applicability.Verdict{}, false
	}
	// The project imports the package by name. That establishes SymbolUsed;
	// whether anything calls it is the rung nox cannot climb at all.
	return applicability.Undeterminable(applicability.SymbolUsed,
		applicability.CallReachable, capability.Unsupported), true
}
