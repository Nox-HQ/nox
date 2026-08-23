package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The CLI has flag-efficacy guards: a flag must demonstrably change behaviour.
// An MCP tool parameter is the same control surface for the agent-facing
// adapter, and it fails the same way — except no human reads the output, so a
// tool that accepts its input and does nothing is quieter still.
//
// Two guards: a registered tool must not be a stub, and every field of a
// handler's input struct must actually be read.

// toolChain matches one `srv.Tool("name")...Handler(s.handleX)` chain. Tools are
// registered from more than one function (registerTools delegates the plugin
// tools to registerPluginTools), so this scans the whole package rather than one
// function body — an earlier version scanned only registerTools and was blind to
// every plugin tool, including the stub it was written to catch.
var toolChain = regexp.MustCompile(`srv\.Tool\("([^"]+)"\)(?:\s*\.\s*\w+\([^\n]*\))*\s*\.\s*Handler\(s\.(\w+)\)`)

// stubbedBody recognises a handler whose whole job is to announce it does not
// work. Returning that as a SUCCESSFUL result is the trap: an agent checking
// isError sees success and takes the sentence as data.
var stubbedBody = regexp.MustCompile(`(?i)not (yet )?implemented|unimplemented|placeholder`)

// packageFiles parses this package's non-test sources.
func packageFiles(t *testing.T) (fset *token.FileSet, files map[string]*ast.File, raws map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	fset = token.NewFileSet()
	files = map[string]*ast.File{}
	raws = map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name) //nolint:gosec // this package's own source
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		// Mode 0 drops comments, so a guard can never match its own prose.
		f, err := parser.ParseFile(fset, name, raw, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = f
		raws[name] = string(raw)
	}
	if len(files) == 0 {
		t.Fatal("found no package sources; the guards below would be vacuous")
	}
	return fset, files, raws
}

// TestNoRegisteredToolIsAStub pins the rule that cost plugin.read_resource its
// registration: a tool nox cannot actually perform must not appear in
// tools/list. Advertising it and returning "not yet implemented" as a success is
// worse than not having it, because the caller cannot tell the difference
// between a working tool with nothing to report and one that never ran.
func TestNoRegisteredToolIsAStub(t *testing.T) {
	fset, files, raws := packageFiles(t)

	bodies := map[string]string{}
	for name, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			bodies[fn.Name.Name] = raws[name][start:end]
		}
	}

	var found int
	for _, raw := range raws {
		for _, m := range toolChain.FindAllStringSubmatch(raw, -1) {
			found++
			tool, handler := m[1], m[2]
			body, ok := bodies[handler]
			if !ok {
				t.Errorf("tool %q binds handler %s, which this package does not define", tool, handler)
				continue
			}
			if stubbedBody.MatchString(body) {
				t.Errorf("tool %q is registered in tools/list, but its handler %s reports that it is not "+
					"implemented — nox must not advertise a capability it does not have", tool, handler)
			}
		}
	}
	// The count is the guard on the guard: an earlier version parsed only one
	// registration function and silently covered 22 of the 25 tools.
	if found < 25 {
		t.Errorf("parsed only %d tool registrations; the pattern has drifted and tools are going unchecked", found)
	}
}

// TestEveryToolInputFieldIsRead is the MCP analogue of the CLI's inert-flag
// guard. A field on a handler input struct becomes a tool PARAMETER in the
// published schema, so a field nothing reads is a parameter the caller can set,
// nox will accept, and no behaviour will reflect.
func TestEveryToolInputFieldIsRead(t *testing.T) {
	_, files, _ := packageFiles(t)

	// Collect every field name actually selected anywhere in the package. Using
	// the AST rather than a substring search matters: ".Plugin" also occurs
	// inside ".PluginScanOutput", so a text search reports a field as read when
	// nothing reads it.
	selected := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				selected[sel.Sel.Name] = true
			}
			return true
		})
	}

	var checked int
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !strings.HasSuffix(ts.Name.Name, "Input") {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				if fld.Tag == nil {
					continue // embedded or untagged: not a published parameter
				}
				for _, ident := range fld.Names {
					if !ident.IsExported() {
						continue
					}
					checked++
					if !selected[ident.Name] {
						t.Errorf("%s.%s is published as a tool parameter but nothing reads it; "+
							"a caller can set it and nox will silently ignore it", ts.Name.Name, ident.Name)
					}
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("checked no tool parameters; the guard is vacuous")
	}
}
