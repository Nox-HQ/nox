package core

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// TestEveryConfigFieldIsReadOrDeclaredInert matches field NAMES, not types, so a
// dead field sharing a name with a live one somewhere else in the module hides
// from it. That limitation is stated in docs/testing-reliability.md; this test
// removes it by using the compiler as the oracle instead of a heuristic.
//
// Every yaml-tagged config field is renamed at once in an in-memory overlay of
// config.go, and the module is built. Each "undefined field" the compiler
// reports names a field something actually reads, resolved by the type checker
// rather than by string matching. A field that produces no error is read by
// nothing — whatever else in the module happens to share its name.
//
// Two passes, so the common case costs one build rather than one per field.
//
// One limitation, stated rather than hidden: the rename is by field NAME, so a
// name shared by several config structs is probed as a group and reported live
// if ANY of them is read. That is the conservative direction — the probe never
// claims a live field is dead — but it means a dead field sharing its name with
// a live SIBLING config field still hides. Names shared with types outside
// config.go, which is what defeated the AST guard, are handled correctly.

// undefinedField pulls the field name out of the compiler's message, which
// reads: cfg.Scan.Include undefined (type ScanSettings has no field or method Include)
var undefinedField = regexp.MustCompile(`has no field or method (\w+)`)

// probeSuffix is appended to every config field name in the overlay. It must not
// collide with a real identifier.
const probeSuffix = "_noxLivenessProbe"

func TestConfigFieldLivenessAgainstTheCompiler(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the module repeatedly; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain available")
	}

	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("reading config.go: %v", err)
	}
	leaves := leafConfigFields(t, string(src))
	if len(leaves) < 30 {
		t.Fatalf("found only %d leaf config fields; the probe covers too little to be worth trusting",
			len(leaves))
	}

	// Pass 1 — rename every leaf at once and collect the fields the compiler
	// names. Cheap, and sound in one direction only: an "undefined field" error
	// proves that field is read, but its ABSENCE proves nothing, because a
	// package that fails to compile stops its dependents being type-checked at
	// all. A field read only by cli/ or server/ is invisible here.
	live := map[string]bool{}
	for _, name := range compilerNamedFields(t, string(src), leaves) {
		live[name] = true
	}

	// Pass 2 — for each field pass 1 could not vouch for, rename that ONE field
	// and build. A dead field's rename breaks nothing, so the build succeeds and
	// the field is dead. A live field's rename breaks whatever reads it,
	// wherever that is, so the build fails. No cascade either way, because only
	// one name moves. Sound in both directions, at the cost of one build per
	// suspect — which is why pass 1 runs first.
	var suspects []string
	for _, f := range leaves {
		if !live[f] {
			suspects = append(suspects, f)
		}
	}
	sort.Strings(suspects)

	declaredInert := map[string]bool{}
	for _, k := range inertConfigKeys {
		for _, f := range k.GoFields {
			declaredInert[f] = true
		}
	}

	dead := probeFieldsInParallel(t, string(src), suspects)
	isDead := make(map[string]bool, len(dead))
	for _, f := range dead {
		isDead[f] = true
		if declaredInert[f] {
			continue
		}
		t.Errorf("no code in this module reads config field %s — renaming it alone still compiles, "+
			"so the compiler says so rather than a name match. Either wire it up, or add it to "+
			"inertConfigKeys with the reason, so an operator who sets it is told it does nothing", f)
	}

	// The reverse direction. An entry that outlived its cause makes nox tell
	// operators a working setting is ignored, which is its own kind of wrong
	// answer. This check lives here rather than beside the AST guard because
	// only the compiler can settle it: CacheSettings.Dir and .TTL share their
	// names with live fields on other config types, so a name-based check
	// reports them read and condemns a correct entry.
	leafSet := make(map[string]bool, len(leaves))
	for _, f := range leaves {
		leafSet[f] = true
	}
	for _, k := range inertConfigKeys {
		for _, f := range k.GoFields {
			if !leafSet[f] || isDead[f] {
				continue
			}
			t.Errorf("inertConfigKeys lists %s (%s), but renaming it breaks the build, so something "+
				"reads it; remove the entry or nox will tell operators a working setting is ignored",
				f, k.Key)
		}
	}
}

// compilerNamedFields renames every leaf at once and returns the field names the
// compiler reports as undefined, i.e. the ones something demonstrably reads.
func compilerNamedFields(t *testing.T, src string, leaves []string) []string {
	t.Helper()
	renamed := renameFields(t, src, leaves)
	out, err := buildWithOverlay(t, renamed)
	if err == nil {
		t.Fatal("renaming every leaf config field still compiled, so nothing reads any of them — " +
			"the overlay did not take effect and this guard is measuring nothing")
	}
	var named []string
	for _, m := range undefinedField.FindAllStringSubmatch(out, -1) {
		named = append(named, strings.TrimSuffix(m[1], probeSuffix))
	}
	if len(named) == 0 {
		t.Fatalf("the build failed but named no undefined fields; the guard cannot tell live from "+
			"dead. Compiler output:\n%s", truncateForTest(out))
	}
	return named
}

// probeFieldsInParallel renames each suspect on its own and returns those whose
// rename leaves the module compiling — the ones nothing reads.
func probeFieldsInParallel(t *testing.T, src string, suspects []string) []string {
	t.Helper()
	if len(suspects) == 0 {
		return nil
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan string)
	var mu sync.Mutex
	var dead []string
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for field := range jobs {
				if _, err := buildWithOverlay(t, renameFields(t, src, []string{field})); err == nil {
					mu.Lock()
					dead = append(dead, field)
					mu.Unlock()
				}
			}
		}()
	}
	for _, s := range suspects {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	sort.Strings(dead)
	return dead
}

// buildWithOverlay builds the module with config.go replaced by src, without
// touching the working tree.
func buildWithOverlay(t *testing.T, src string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	probe := filepath.Join(dir, "config_probe.go")
	if err := os.WriteFile(probe, []byte(src), 0o600); err != nil {
		t.Fatalf("writing overlay file: %v", err)
	}
	absConfig, err := filepath.Abs("config.go")
	if err != nil {
		t.Fatalf("resolving config.go: %v", err)
	}
	overlay := filepath.Join(dir, "overlay.json")
	body, err := json.Marshal(map[string]any{"Replace": map[string]string{absConfig: probe}})
	if err != nil {
		t.Fatalf("marshalling overlay: %v", err)
	}
	if err := os.WriteFile(overlay, body, 0o600); err != nil {
		t.Fatalf("writing overlay: %v", err)
	}
	cmd := exec.Command("go", "build", "-gcflags=all=-e", "-overlay", overlay, "./...") //nolint:gosec // fixed args
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// leafConfigFields returns the yaml-tagged field names in src whose type is not
// itself a config struct.
//
// Container fields are excluded because renaming one breaks every access chain
// at the first hop: `cfg.Scan.Exclude` then fails on `.Scan` and the compiler
// never resolves `.Exclude`, so every leaf beneath it looks dead. Containers are
// covered by TestEveryConfigFieldIsReadOrDeclaredInert.
func leafConfigFields(t *testing.T, src string) []string {
	t.Helper()
	_, names := walkConfigFields(t, src, nil)
	return names
}

// renameFields returns src with each named field's declaration suffixed.
func renameFields(t *testing.T, src string, only []string) string {
	t.Helper()
	want := make(map[string]bool, len(only))
	for _, n := range only {
		want[n] = true
	}
	out, _ := walkConfigFields(t, src, want)
	return out
}

// walkConfigFields parses src, renames the leaf fields selected by want (nil
// selects all), and returns the rewritten source plus the leaf field names.
func walkConfigFields(t *testing.T, src string, want map[string]bool) (rewritten string, leafNames []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "config.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing config.go: %v", err)
	}

	containers := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if _, isStruct := ts.Type.(*ast.StructType); isStruct {
			containers[ts.Name.Name] = true
		}
		return true
	})

	type edit struct {
		offset int
		name   string
	}
	var edits []edit
	seen := map[string]bool{}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil || !strings.Contains(fld.Tag.Value, "yaml:") {
				continue
			}
			if containers[baseTypeName(fld.Type)] {
				continue
			}
			for _, ident := range fld.Names {
				if !ident.IsExported() {
					continue
				}
				if !seen[ident.Name] {
					seen[ident.Name] = true
					names = append(names, ident.Name)
				}
				if want != nil && !want[ident.Name] {
					continue
				}
				edits = append(edits, edit{offset: fset.Position(ident.End()).Offset, name: ident.Name})
			}
		}
		return true
	})

	// Apply back-to-front so earlier offsets stay valid.
	out := src
	for i := len(edits) - 1; i >= 0; i-- {
		out = out[:edits[i].offset] + probeSuffix + out[edits[i].offset:]
	}
	sort.Strings(names)
	return out, names
}

// baseTypeName returns the underlying named type of a field's type expression,
// looking through pointers, slices, arrays and maps so []AnalyzerRuleConfig is
// recognised as a container too.
func baseTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.ArrayType:
		return baseTypeName(t.Elt)
	case *ast.MapType:
		return baseTypeName(t.Value)
	default:
		return ""
	}
}

// truncateForTest keeps a failure message readable.
func truncateForTest(s string) string {
	const limit = 2000
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n… (truncated)"
}
