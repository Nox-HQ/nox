package deps

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/applicability"
	"github.com/nox-hq/nox/core/callgraph"
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

// applyReachMetadata writes a reachability result onto a finding's metadata.
//
// One function, called unconditionally, because the previous arrangement wrote
// these keys only for the outcomes that concluded something. An analysis that
// ran and could not tell wrote nothing, and nothing is how a scanner says "we
// never looked".
//
// reach_limitations is the machine-readable half of reach_scope. The prose
// description is for a person reading `nox why`; a CI job or an agent deciding
// whether to trust an absent reachability answer needs the named reasons, and
// parsing them back out of an English sentence is not a contract.
func applyReachMetadata(meta map[string]string, r reach.Result) {
	if meta == nil || r.Level == "" {
		return
	}
	// The LEVEL, named. `go list -deps` establishes that the affected import is
	// in the linked set, which is symbol_referenced and nothing above it. This
	// used to be written as meta["reachable"], a name that reads as
	// call_reachable, and the capability matrix then counted it as the
	// reachability capability — evidence for one proposition establishing a
	// later one, which is the invariant this vocabulary exists to hold.
	meta["reach_level"] = string(r.Level)
	meta["reach_outcome"] = string(r.Outcome)
	meta["reach_scope"] = r.Scope.Describe()
	if len(r.Scope.Limitations) > 0 {
		names := make([]string, 0, len(r.Scope.Limitations))
		for _, l := range r.Scope.Limitations {
			names = append(names, string(l))
		}
		sort.Strings(names)
		meta["reach_limitations"] = strings.Join(names, ",")
	}
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

// goCallReachable asks whether execution can reach a function in THIS module
// that calls into one of the advisory's affected import paths.
//
// It is milestone 7.3's composition: `go list -deps` establishes that the build
// LINKS the affected package (applicability.SymbolUsed), and the call graph
// answers the next rung — whether anything in this build actually reaches for
// it from somewhere that runs.
//
// Only positive answers are returned, and that is the whole design. A syntactic
// call graph cannot see interface dispatch, function values or reflection, so
// "no path found" is not "no path exists" — it is the search coming up empty,
// which leaves the rung unclimbed rather than refuted. core/callgraph never
// refutes for the same reason.
//
// The witness is the real chain of calls, so a reader can follow it rather than
// take the rung on trust.
func goCallReachable(g *callgraph.Graph, root string, affected []string) (path []string, ok bool) {
	if g == nil || len(affected) == 0 {
		return nil, false
	}
	var best []string
	for _, imp := range affected {
		for _, caller := range g.CallersOfPackage(imp) {
			p, kind := g.PathToFunc(caller)
			// Only a CONCRETE entry establishes that execution reaches this.
			// An exported function is reachable by somebody in principle, which
			// is the weaker claim reach.AttackerEntryPathExists exists to keep
			// separate — and a test entry establishes that the test suite runs
			// it, not the program.
			if kind != callgraph.EntryConcrete {
				continue
			}
			if best == nil || len(p) < len(best) {
				best = p
			}
		}
	}
	_ = root
	if best == nil {
		return nil, false
	}
	return best, true
}

// symbolHit is a call path from this module to a function an advisory lists.
type symbolHit struct {
	importPath, symbol string
	// fromAdvisory is true when the advisory's own publisher listed the symbol
	// (OSV imports[].symbols), false when only NOX Intelligence's patch
	// analysis did.
	fromAdvisory bool
	path         []string
}

// goListedSymbolHit looks for a concrete call path from this module to a
// function the advisory lists as affected, by the publisher or by nox_symbols.
//
// It can only raise. A listed symbol is a hint with a precision of roughly
// 0.3 to 0.5 and partial recall, so "no listed symbol is called" is not
// evidence of anything, and the caller must treat a false result as "nothing
// found", never as a reason to lower a finding. Only package-level functions
// can be found: a method call's receiver type is not known from syntax.
func goListedSymbolHit(g *callgraph.Graph, ov *osvVuln, module string) (symbolHit, bool) {
	if g == nil {
		return symbolHit{}, false
	}
	paths := map[string]struct{}{}
	for _, aff := range ov.Affected {
		if aff.Package.Name != module {
			continue
		}
		for _, im := range aff.EcosystemSpecific.Imports {
			if im.Path != "" {
				paths[im.Path] = struct{}{}
			}
		}
	}
	for _, as := range ov.Symbols {
		if as.Package != module || as.Status != vulnsource.SymbolStatusOK {
			continue
		}
		for _, im := range as.Imports {
			paths[im.Path] = struct{}{}
		}
		for _, cs := range as.Symbols {
			if cs.Package != "" {
				paths[cs.Package] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)

	advisorySet := func(importPath string) map[string]bool {
		out := map[string]bool{}
		for _, aff := range ov.Affected {
			if aff.Package.Name != module {
				continue
			}
			for _, im := range aff.EcosystemSpecific.Imports {
				if im.Path == importPath {
					for _, s := range im.Symbols {
						out[s] = true
					}
				}
			}
		}
		return out
	}

	var best symbolHit
	found := false
	for _, importPath := range ordered {
		fromAdvisory := advisorySet(importPath)
		for _, sym := range ov.ListedSymbols(module, importPath) {
			for _, caller := range g.CallersOfSymbol(importPath, sym) {
				p, kind := g.PathToFunc(caller)
				// Only a concrete entry, as in goCallReachable.
				if kind != callgraph.EntryConcrete {
					continue
				}
				if !found || len(p) < len(best.path) {
					best = symbolHit{importPath: importPath, symbol: sym, fromAdvisory: fromAdvisory[sym], path: p}
					found = true
				}
			}
		}
	}
	return best, found
}

// raiseOnListedSymbol records a call path to a symbol the advisory lists and,
// when the climb had not already reached a call path, raises it to one.
//
// Raise-only, by construction: it returns the verdict unchanged when no listed
// symbol is called, and it never touches a NotImpacting verdict, which rests on
// the publisher's own statement of which packages are affected.
func raiseOnListedSymbol(v applicability.Verdict, meta map[string]string, g *callgraph.Graph, ov *osvVuln, module string) applicability.Verdict {
	hit, ok := goListedSymbolHit(g, ov, module)
	if !ok {
		return v
	}
	meta["affected_symbol_reached"] = hit.importPath + "." + hit.symbol
	if hit.fromAdvisory {
		meta["affected_symbol_basis"] = "advisory"
	} else {
		meta["affected_symbol_basis"] = "nox_symbols"
	}
	if v.Outcome == applicability.NotImpacting {
		return v
	}
	if v.Outcome == applicability.Impacting && !applicability.CallReachable.Above(v.Reached) {
		return v // already at or above a call path
	}
	return applicability.Established(applicability.CallReachable, hit.path)
}

// jsListedSymbolHit looks for a project source file that references an export
// NOX Intelligence's analysis of the fix lists as changed.
//
// Only symbols the service could place on a public import specifier carry a
// Package (`nodemailer`, `nodemailer/lib/addressparser`); an internal helper
// has none and cannot be matched, so it is never searched for. As with Go, this
// can only raise: a project that does not reference a listed export has shown
// nothing, because a binding can be passed on, re-exported or used through a
// dependency.
func jsListedSymbolHit(src *sourceImports, ov *osvVuln, module string) (spec, symbol string, use depimports.JSUse, ok bool) {
	if src == nil {
		return "", "", depimports.JSUse{}, false
	}
	type cand struct{ spec, name string }
	var cands []cand
	for _, as := range ov.Symbols {
		if as.Package != module || as.Status != vulnsource.SymbolStatusOK {
			continue
		}
		for _, cs := range as.Symbols {
			if cs.Name == "" || cs.Package == "" {
				continue
			}
			if cs.Package != module && !strings.HasPrefix(cs.Package, module+"/") {
				continue // another package's specifier never matches this one
			}
			cands = append(cands, cand{cs.Package, cs.Name})
		}
	}
	if len(cands) == 0 {
		return "", "", depimports.JSUse{}, false
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].spec != cands[j].spec {
			return cands[i].spec < cands[j].spec
		}
		return cands[i].name < cands[j].name
	})
	ix := src.get()
	if !ix.Known("npm") {
		return "", "", depimports.JSUse{}, false
	}
	for _, c := range cands {
		if u, found := ix.JSSymbolUse(c.spec, c.name); found {
			return c.spec, c.name, u, true
		}
	}
	return "", "", depimports.JSUse{}, false
}

// raiseOnJSListedSymbol is raiseOnListedSymbol for npm. The evidence is weaker
// than Go's and is labelled so: a reference in non-test project source, not a
// call path from an entry point, because nox has no JavaScript call graph.
// affected_symbol_evidence says which, and the printed sentence repeats it.
func raiseOnJSListedSymbol(v applicability.Verdict, meta map[string]string, src *sourceImports, ov *osvVuln, pkg Package) applicability.Verdict {
	if !strings.EqualFold(pkg.Ecosystem, "npm") || v.Outcome == applicability.NotImpacting {
		return v
	}
	spec, name, use, ok := jsListedSymbolHit(src, ov, pkg.Name)
	if !ok {
		return v
	}
	where := fmt.Sprintf("%s:%d", use.File, use.Line)
	meta["affected_symbol_reached"] = spec + "." + name
	meta["affected_symbol_basis"] = "nox_symbols"
	meta["affected_symbol_evidence"] = "source_reference"
	meta["affected_symbol_site"] = where
	if v.Outcome == applicability.Impacting && !applicability.CallReachable.Above(v.Reached) {
		return v
	}
	return applicability.Established(applicability.CallReachable, []string{where + " references " + spec + "." + name})
}

// sourceReferenceSentence states a JavaScript symbol hit without borrowing the
// Go call-path wording: a reference is not a path from an entry point.
func sourceReferenceSentence(meta map[string]string) string {
	return fmt.Sprintf("project source references %s (%s), an export the analysis of the fix lists as changed; "+
		"whether execution reaches it was not established, and neither was %q",
		meta["affected_symbol_reached"], meta["affected_symbol_site"], applicability.AttackerReachable)
}
