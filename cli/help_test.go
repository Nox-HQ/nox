package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// dispatchedCommands reads the commands `run` dispatches from its own source,
// so a command added to the switch and not to the usage text fails here
// instead of shipping undiscoverable.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}
	var cmds []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if id, ok := sw.Tag.(*ast.Ident); !ok || id.Name != "command" {
				return true
			}
			for _, stmt := range sw.Body.List {
				for _, e := range stmt.(*ast.CaseClause).List {
					if lit, ok := e.(*ast.BasicLit); ok {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							cmds = append(cmds, s)
						}
					}
				}
			}
			return false
		})
		return false
	})
	return cmds
}

// Five commands were dispatched and absent from `nox --help`: replay, why,
// intel, verify-secrets and variants. Nothing tied the usage text to the
// switch, so each was added to one and not the other.
func TestTopLevelHelpListsEveryCommand(t *testing.T) {
	cmds := dispatchedCommands(t)
	if len(cmds) < 30 {
		t.Fatalf("read only %d commands from run's switch; the reader is broken, so this test would prove nothing", len(cmds))
	}
	usage := captureStderr(t, func() { run([]string{"--help"}) })
	for _, c := range cmds {
		listed := false
		for _, line := range strings.Split(usage, "\n") {
			if f := strings.Fields(line); len(f) > 0 && f[0] == c {
				listed = true
				break
			}
		}
		if !listed {
			t.Errorf("command %q is dispatched but `nox --help` does not list it", c)
		}
	}
}

// A request for help is not an unknown subcommand. These commands dispatch on
// their first argument and used to report `--help` as a mistake, exit 2.
func TestGroupCommandsAnswerHelp(t *testing.T) {
	for _, c := range []string{"baseline", "protect", "plugin", "registry", "intel", "vex", "completion", "uri", "doctor"} {
		for _, h := range []string{"--help", "-h", "help"} {
			var code int
			out := captureStdout(t, func() { code = run([]string{c, h}) })
			if code != 0 {
				t.Errorf("nox %s %s: exit %d, want 0", c, h, code)
			}
			if !strings.Contains(out, "Usage: nox "+c) {
				t.Errorf("nox %s %s: stdout does not carry the usage line; got %q", c, h, out)
			}
		}
	}
}
