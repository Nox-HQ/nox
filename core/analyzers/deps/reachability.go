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
