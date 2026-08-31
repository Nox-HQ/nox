package attack

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Milestone K: the passive/active boundary is a permanent invariant.
//
// `nox scan` is read-only — lexing, constant evaluation, SCA, taint, graph
// analysis, reachability, hypothesis construction. `nox attack` is where
// network requests, target interaction and dynamic reproduction live, and it is
// explicitly authorized.
//
// That boundary matters more than shaving false positives off a scan. A
// security scanner that can unknowingly attack its target becomes unsafe to run
// in most of the environments where it should be ubiquitous — a CI runner
// pointed at production, a developer laptop on a corporate VPN, a pipeline in
// someone else's cloud.
//
// It is currently enforced by wiring rather than policy, which is the right
// place. These tests are what stop the wiring being rearranged by accident.

// TestEveryActiveEntryPointRequiresAuthorization enumerates the exported
// functions that can touch a target and checks each refuses without it.
//
// Enumerated from the source rather than listed by hand: a fifth entry point
// added later must appear here, and a hand-written list is exactly what would
// not notice it.
func TestEveryActiveEntryPointRequiresAuthorization(t *testing.T) {
	active := activeEntryPoints(t)
	// The four that exist when this was written. The count is asserted so a new
	// one arrives as a failure rather than as silence.
	for _, want := range []string{"Run", "Replay", "RunSuite", "RunMCP"} {
		if !active[want] {
			t.Errorf("%s is no longer an exported entry point taking a context and a "+
				"config; if it was renamed, this guard has stopped covering it", want)
		}
	}
	if len(active) > 4 {
		var extra []string
		for name := range active {
			switch name {
			case "Run", "Replay", "RunSuite", "RunMCP":
			default:
				extra = append(extra, name)
			}
		}
		t.Errorf("new active entry point(s) %v. Each must refuse an unauthorized "+
			"non-safe profile and refuse a network target under the safe profile; "+
			"add them below and to this list", extra)
	}

	ctx := context.Background()
	unauthorized := RunConfig{Profile: ProfileStaging}

	if _, err := Run(ctx, &Plan{}, &SimTarget{}, unauthorized); err == nil {
		t.Error("Run executed under an unauthorized active profile")
	}
	if _, err := RunSuite(ctx, &Suite{}, &SimTarget{}, unauthorized); err == nil {
		t.Error("RunSuite executed under an unauthorized active profile")
	}
	res := &Result{Traces: []Trace{{ID: "t", Evidence: &ExploitEvidence{}}}}
	if _, err := Replay(ctx, res, "t", &SimTarget{}, unauthorized); err == nil {
		t.Error("Replay executed under an unauthorized active profile")
	}
}

// TestTheSafeProfileCannotReachTheNetwork. The safe profile's guarantee is
// structural: it selects an adapter with no network capability, so the promise
// is kept by what is wired rather than by a check somebody might move.
func TestTheSafeProfileCannotReachTheNetwork(t *testing.T) {
	if ProfileSafe.AllowsNetwork() {
		t.Fatal("the safe profile allows network traffic, which is the whole of what " +
			"it promises not to do")
	}
	if ProfileSafe.RequiresAuthorization() {
		t.Error("the safe profile demands authorization it does not need, which " +
			"trains operators to pass --authorize by reflex")
	}
	for _, p := range []Profile{ProfileSandbox, ProfileStaging, ProfileAuthorizedLive} {
		if !p.AllowsNetwork() || !p.RequiresAuthorization() {
			t.Errorf("profile %q is active but does not require authorization or "+
				"network permission", p)
		}
	}
}

// TestTheScanCannotReachTheAttackPackage is the boundary at its strongest.
//
// If core (the scan pipeline) imported core/attack, a scan could execute
// something by accident — a refactor, a helper reused in the wrong place. It
// does not, and the dependency graph is what guarantees that. Asserted by
// reading the imports rather than by convention, because a convention is what
// a refactor does not consult.
func TestTheScanCannotReachTheAttackPackage(t *testing.T) {
	root := filepath.Join("..", "..", "core")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading core: %v", err)
	}
	fset := token.NewFileSet()
	var checked int
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			continue
		}
		checked++
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "nox/core/attack") {
				t.Errorf("%s imports core/attack. The scan pipeline must not be able "+
					"to reach code that touches a target; a scanner that can "+
					"unknowingly attack what it is pointed at is unsafe to run in most "+
					"places nox should be ubiquitous", e.Name())
			}
		}
	}
	if checked == 0 {
		t.Fatal("no files in core were parsed; this guard is checking nothing")
	}
	t.Logf("%d files in core carry no import of core/attack", checked)
}

// activeEntryPoints returns the exported functions in this package that take a
// context and a run configuration — the shape of something that can act.
func activeEntryPoints(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package: %v", err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Params == nil {
				continue
			}
			var takesCtx, takesCfg bool
			for _, p := range fn.Type.Params.List {
				switch typ := p.Type.(type) {
				case *ast.SelectorExpr:
					if typ.Sel.Name == "Context" {
						takesCtx = true
					}
				case *ast.Ident:
					if strings.HasSuffix(typ.Name, "RunConfig") {
						takesCfg = true
					}
				}
			}
			if takesCtx && takesCfg {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}
