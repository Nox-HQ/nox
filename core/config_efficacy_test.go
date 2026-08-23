package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UnknownConfigKeys already reports keys nox does not understand, on the
// principle that a security tool which silently ignores configuration reports on
// a policy the operator did not ask for. That check answers "does this key
// parse?". It cannot answer "does this key DO anything?", so a field that sits
// in ScanConfig and is read by nothing passes it in silence — the operator
// writes it, nox accepts it, and nothing happens.
//
// This is the same question the CLI's flag-efficacy guards ask, one layer down.

// TestEveryConfigFieldIsReadOrDeclaredInert requires each yaml-tagged config
// field either to be read somewhere in the module or to be listed, with a
// reason, in the inert table that IneffectiveConfigKeys reports from. There is
// no third option: a field nobody reads and nobody has declared inert is a
// setting the operator cannot tell is doing nothing.
func TestEveryConfigFieldIsReadOrDeclaredInert(t *testing.T) {
	selected := selectorsInModule(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "config.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing config.go: %v", err)
	}

	declaredInert := map[string]bool{}
	for _, k := range inertConfigKeys {
		// A parent key covers its children: declaring "compliance" inert covers
		// compliance.framework, which no one can act on either.
		for _, f := range k.GoFields {
			declaredInert[f] = true
		}
	}

	var checked int
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil || !strings.Contains(fld.Tag.Value, "yaml:") {
				continue
			}
			for _, ident := range fld.Names {
				if !ident.IsExported() {
					continue
				}
				checked++
				if selected[ident.Name] || declaredInert[ident.Name] {
					continue
				}
				t.Errorf("%s.%s is a documented-looking config field that nothing in the module reads. "+
					"Either wire it up, or add it to inertConfigKeys with the reason, so an operator who "+
					"sets it is told it does nothing instead of assuming it took effect",
					ts.Name.Name, ident.Name)
			}
		}
		return true
	})
	if checked == 0 {
		t.Fatal("checked no config fields; the guard is vacuous")
	}
}

// TestInertConfigKeysAreActuallyInert is the reverse direction. A key listed as
// inert that something has since started reading is a stale apology: nox would
// warn the operator that a setting they rely on does nothing.
func TestInertConfigKeysAreActuallyInert(t *testing.T) {
	selected := selectorsInModule(t)
	for _, k := range inertConfigKeys {
		if len(k.GoFields) == 0 {
			t.Errorf("inert key %s names no Go fields, so nothing checks it is still inert", k.Key)
		}
		for _, f := range k.GoFields {
			if selected[f] {
				t.Errorf("inertConfigKeys lists %s (%s), but something now reads it; remove the entry or "+
					"nox will tell operators a working setting is ignored", f, k.Key)
			}
		}
		if strings.TrimSpace(k.Reason) == "" {
			t.Errorf("inert key %s has no reason; the operator is told it does nothing but not why", k.Key)
		}
	}
}

// selectorsInModule returns every field name selected anywhere in the module's
// non-test, non-generated Go source. Selector expressions rather than a text
// search: ".Cache" also occurs inside ".CacheDir", so a substring match reports
// a dead field as live.
func selectorsInModule(t *testing.T) map[string]bool {
	t.Helper()
	root := ".."
	selected := map[string]bool{}
	var files int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable dir is not this guard's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "gen", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		// config.go is included: a field read by an accessor method there (e.g.
		// GeneratedPathsConfig.Extend, folded into GeneratedPaths()) is genuinely
		// wired, and the declaration itself is not a selector expression, so it
		// cannot make a dead field look live.
		raw, err := os.ReadFile(path) //nolint:gosec // module source
		if err != nil {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, raw, 0)
		if err != nil {
			return nil // a file this guard cannot parse simply contributes nothing
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				selected[sel.Sel.Name] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if files < 100 {
		t.Fatalf("only parsed %d module files; the guard would report live fields as dead", files)
	}
	return selected
}

// TestIneffectiveConfigKeysReportsOnlyWhatWasWritten pins the reporting side.
// Listing every inert key regardless of the config would train operators to
// ignore the warning; listing none when they wrote one is the silence this
// whole mechanism exists to end.
func TestIneffectiveConfigKeysReportsOnlyWhatWasWritten(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(body), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}
		return dir
	}
	keys := func(got []InertConfigKey) []string {
		out := make([]string, 0, len(got))
		for _, k := range got {
			out = append(out, k.Key)
		}
		return out
	}

	t.Run("a config using only live keys reports nothing", func(t *testing.T) {
		dir := write(t, "scan:\n  exclude:\n    - vendor/**\n")
		if got := IneffectiveConfigKeys(dir); len(got) > 0 {
			t.Errorf("reported %v for a config that sets only working keys", keys(got))
		}
	})

	t.Run("only the inert keys actually written are reported", func(t *testing.T) {
		dir := write(t, "scan:\n  exclude:\n    - vendor/**\n  include:\n    - src/**\n")
		got := keys(IneffectiveConfigKeys(dir))
		if len(got) != 1 || got[0] != "scan.include" {
			t.Errorf("reported %v, want exactly [scan.include]", got)
		}
	})

	t.Run("a parent key is reported even when only a child is set", func(t *testing.T) {
		dir := write(t, "compliance:\n  framework: soc2\n")
		got := keys(IneffectiveConfigKeys(dir))
		if len(got) != 1 || got[0] != "compliance" {
			t.Errorf("reported %v, want exactly [compliance]", got)
		}
	})

	t.Run("presence is what counts, not the value", func(t *testing.T) {
		// `include: []` still says the operator believes include does something.
		dir := write(t, "scan:\n  include: []\n")
		if got := keys(IneffectiveConfigKeys(dir)); len(got) != 1 {
			t.Errorf("reported %v for an explicitly empty inert key; the operator still wrote it", got)
		}
	})

	t.Run("no config file is not a finding", func(t *testing.T) {
		if got := IneffectiveConfigKeys(t.TempDir()); got != nil {
			t.Errorf("reported %v with no .nox.yaml present", keys(got))
		}
	})

	t.Run("every reported key carries its reason", func(t *testing.T) {
		dir := write(t, "cache:\n  disabled: true\n")
		got := IneffectiveConfigKeys(dir)
		if len(got) != 1 {
			t.Fatalf("reported %v, want exactly [cache]", keys(got))
		}
		if strings.TrimSpace(got[0].Reason) == "" {
			t.Error("the operator is told the key does nothing but not what nox does instead")
		}
	})
}
