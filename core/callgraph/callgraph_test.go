package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/reach"
)

// module writes a small Go module and returns its root.
func module(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module example.com/m\n\ngo 1.21\n"
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// THE property. This package never refutes, and the guarantee is structural
// rather than a rule somebody has to remember.
//
// A syntactic graph cannot see interface dispatch, function values, struct
// fields holding funcs, generics, embedding, reflection or generated code.
// Every one is a call it does not have, and each is a place a path could hide.
// So no Scope it builds may support a universal claim, and reach.Refute must
// decline to construct one from it.
//
// A scanner that reported "no call path" from a graph like this would be
// reporting its own blind spot as an all-clear — the single failure the whole
// capability model exists to prevent.
func TestTheGraphCanNeverRefuteACallPath(t *testing.T) {
	// Deliberately the friendliest possible input: one package, one call, no
	// interfaces, no function values, nothing dynamic. If any module could
	// justify a complete scope this is it, and it must not.
	dir := module(t, map[string]string{
		"main.go": `package main

func helper() {}

func main() { helper() }
`,
	})
	g := BuildGo(dir)
	scope := g.Scope()

	if scope.Complete() {
		t.Fatal("the scope reports itself complete, so reach.Refute would build a negative " +
			"from a graph that cannot see interface dispatch")
	}
	subject := evidence.Subject{Kind: evidence.SubjectSymbol, ID: "helper"}
	if _, ok := reach.Refute(subject, reach.CallPathExists, scope); ok {
		t.Error("reach.Refute accepted this scope; a finding could be suppressed on the " +
			"strength of a path this analysis merely did not find")
	}
	// And the result it hands back instead says so rather than saying nothing.
	r := reach.Undeterminable(subject, reach.CallPathExists, scope)
	if !strings.Contains(r.Describe(), "unknown") {
		t.Errorf("the undetermined result does not read as unknown: %q", r.Describe())
	}
}

// A found path is a real chain of calls, not a claim.
func TestAWitnessPathIsTheActualCallChain(t *testing.T) {
	dir := module(t, map[string]string{
		"main.go": `package main

func third() {}
func second() { third() }
func first() { second() }

func main() { first() }
`,
	})
	g := BuildGo(dir)
	path, kind := g.PathToFunc("third")
	if kind != EntryConcrete {
		t.Fatalf("reached = %s, want concrete (main calls into this chain)", kind)
	}
	want := []string{"main", "first", "second", "third"}
	if len(path) != len(want) {
		t.Fatalf("path = %v, want %v", path, want)
	}
	for i := range want {
		if path[i] != want[i] {
			t.Errorf("path[%d] = %q, want %q — a witness that is not the real chain is worse "+
				"than no witness", i, path[i], want[i])
		}
	}
}

// A function nothing calls gets no path, and the absence is Unknown rather than
// a refutation. `unused` here really is unreferenced, and this package still
// declines to say so.
func TestAnUnreachedFunctionIsNotRefuted(t *testing.T) {
	dir := module(t, map[string]string{
		"main.go": `package main

func unused() {}

func main() {}
`,
	})
	g := BuildGo(dir)
	path, kind := g.PathToFunc("unused")
	if len(path) > 1 {
		t.Errorf("a function nothing calls got a path of %d: %v", len(path), path)
	}
	if kind == EntryConcrete {
		t.Error("an unreferenced unexported function was reported as a concrete entry point")
	}
}

// Concrete and exported entry points are different claims and must not merge.
//
// The first version of this package counted every exported function as an entry
// point, which on nox's own tree made 5,088 of 7,652 functions entries. Every
// query then returned a path of length one — "this exported function is
// reachable because it is exported" — true, trivial, and reading like a much
// stronger claim than it is.
func TestExportedIsNotTheSameEntryAsMain(t *testing.T) {
	dir := module(t, map[string]string{
		"lib/lib.go": `package lib

// Exported is reachable by an outside caller, and nothing here calls it.
func Exported() {}

func internal() {}
`,
		"main.go": `package main

func main() {}
`,
	})
	g := BuildGo(dir)

	concrete := g.EntryPoints(EntryConcrete)
	if len(concrete) != 1 || concrete[0] != "main" {
		t.Errorf("concrete entry points = %v, want exactly [main]", concrete)
	}
	all := g.EntryPoints(EntryExported)
	if len(all) < 2 {
		t.Errorf("entry points at exported-or-stronger = %v, want main and lib.Exported", all)
	}

	if _, kind := g.PathToFunc("lib.Exported"); kind != EntryExported {
		t.Errorf("lib.Exported reached = %s, want exported — nothing in this module calls it, "+
			"and reporting it as concrete would claim execution begins there", kind)
	}
	if _, kind := g.PathToFunc("lib.internal"); kind != NotAnEntry {
		t.Errorf("an unexported, uncalled function reached = %s, want none", kind)
	}
}

// Calls between packages of the same module resolve. Without the module path
// from go.mod they cannot, and most of a real program's call graph is
// cross-package — 21% of in-module calls resolved before this, 29% after.
func TestCrossPackageCallsInsideTheModuleResolve(t *testing.T) {
	dir := module(t, map[string]string{
		"lib/lib.go": `package lib

func Target() {}
`,
		"main.go": `package main

import "example.com/m/lib"

func main() { lib.Target() }
`,
	})
	g := BuildGo(dir)
	path, kind := g.PathToFunc("lib.Target")
	if kind != EntryConcrete {
		t.Fatalf("reached = %s, want concrete; the cross-package edge did not resolve", kind)
	}
	if len(path) != 2 || path[0] != "main" {
		t.Errorf("path = %v, want [main lib.Target]", path)
	}
}

// A call into the standard library is not the same kind of not-knowing as an
// unresolved dispatch. Counting them together made the resolved ratio
// meaningless — 21% on nox's own tree, almost all of it fmt.Sprintf.
func TestStdlibCallsAreCountedApartFromUnresolvedDispatch(t *testing.T) {
	dir := module(t, map[string]string{
		"main.go": `package main

import "fmt"

func main() { fmt.Println("hi") }
`,
	})
	g := BuildGo(dir)
	unresolved, _, external := g.Unresolved()
	if external == 0 {
		t.Error("a call into fmt was not counted as external")
	}
	if unresolved != 0 {
		t.Errorf("a stdlib call was counted as an unresolved dispatch (%d); the two are "+
			"different kinds of not-knowing and only one is a hole in this module's graph",
			unresolved)
	}
}

// Interface dispatch is named as the limitation it is.
func TestInterfaceDispatchIsRecordedAsALimitation(t *testing.T) {
	dir := module(t, map[string]string{
		"main.go": `package main

type Doer interface{ Do() }

func run(d Doer) { d.Do() }

func main() { run(nil) }
`,
	})
	g := BuildGo(dir)
	var found bool
	for _, l := range g.Scope().Limitations {
		if l == reach.UnresolvedDispatch {
			found = true
		}
	}
	if !found {
		t.Errorf("a call through an interface did not record unresolved_dispatch; "+
			"limitations = %v", g.Scope().Limitations)
	}
}

// The same tree produces the same graph. A witness path that reordered between
// runs would make findings.json non-reproducible.
func TestGraphIsDeterministic(t *testing.T) {
	files := map[string]string{
		"main.go": `package main

func c() {}
func b() { c() }
func a() { c() }

func main() { a(); b() }
`,
	}
	dir := module(t, files)
	first, _ := BuildGo(dir).PathToFunc("c")
	for i := 0; i < 8; i++ {
		again, _ := BuildGo(dir).PathToFunc("c")
		if strings.Join(first, ",") != strings.Join(again, ",") {
			t.Fatalf("run %d produced %v, first run produced %v", i+2, again, first)
		}
	}
}

// A directory that is not a module still parses; it simply cannot resolve
// cross-package calls. It must not panic or claim more than it has.
func TestNoGoModStillBuilds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n\nfunc F() {}\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	g := BuildGo(dir)
	if g.Len() != 1 {
		t.Errorf("graph holds %d functions, want 1", g.Len())
	}
	if g.Scope().Complete() {
		t.Error("a graph with no module path called its scope complete")
	}
}
