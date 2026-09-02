package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// sinkArgsFor returns the argument-shape evidence recorded for a call.
func sinkArgsFor(t *testing.T, src, call string) (shellProgram, firstArgTainted bool, argCount int) {
	t.Helper()
	for _, u := range ExtractUnits("a.go", lexctx.LangGo, []byte(src)) {
		for i := range u.Stmts {
			for name, info := range u.Stmts[i].SinkArgs {
				if strings.Contains(name, call) {
					return info.ShellProgram, info.FirstArgTainted, info.ArgCount
				}
			}
		}
	}
	t.Fatalf("no sink args recorded for %q", call)
	return
}

// Go's two standard safe forms — a parameterized query and an arg-vector exec —
// were false positives whenever the value was actually tainted. The corpus
// could not see it: clean_safe_db.go took its values as function PARAMETERS, so
// nothing flowed and the sample stayed clean whether the guards worked or not.
func TestGoArgVectorExecIsNotAShell(t *testing.T) {
	src := "package p\nimport \"os/exec\"\nfunc f(dir string) { exec.Command(\"ls\", \"-la\", \"--\", dir) }\n"
	shell, firstTainted, _ := sinkArgsFor(t, src, "exec.Command")
	if shell {
		t.Error(`exec.Command("ls", …) reported a shell program`)
	}
	if firstTainted {
		t.Error("a string-literal program was recorded as a tainted first argument")
	}
}

// …but naming a shell as the program voids the exemption. This is what keeps
// tp_cmdinjection.go a true positive.
func TestGoShellProgramIsDetected(t *testing.T) {
	for _, prog := range []string{`"sh"`, `"bash"`, `"/bin/sh"`, `"/usr/bin/env"`} {
		src := "package p\nimport \"os/exec\"\nfunc f(c string) { exec.Command(" + prog + ", \"-c\", c) }\n"
		shell, _, _ := sinkArgsFor(t, src, "exec.Command")
		if !shell {
			t.Errorf("exec.Command(%s, \"-c\", …) was not recognised as running a shell", prog)
		}
	}
}

// A program named by a variable is UNKNOWN, not a shell. Reading it as one
// would void the exemption wherever the program is computed.
func TestGoVariableProgramIsNotAShell(t *testing.T) {
	src := "package p\nimport \"os/exec\"\nfunc f(prog, arg string) { exec.Command(prog, arg) }\n"
	shell, _, _ := sinkArgsFor(t, src, "exec.Command")
	if shell {
		t.Error("a variable program name was treated as a shell")
	}
}

// A parameterized query passes the value AFTER the query string, so the taint is
// not in the first argument — the shape the exemption keys on.
func TestGoParameterizedQueryKeepsTaintOutOfArgZero(t *testing.T) {
	src := "package p\nimport \"database/sql\"\nfunc f(db *sql.DB, id string) { db.Query(\"SELECT x FROM t WHERE id = $1\", id) }\n"
	_, firstTainted, argCount := sinkArgsFor(t, src, "db.Query")
	if firstTainted {
		t.Error("a parameterized query recorded the taint in the query string")
	}
	if argCount < 2 {
		t.Errorf("argCount = %d, want >= 2; the exemption requires a params argument", argCount)
	}
}

// Concatenating into the query string puts the taint in argument zero, which is
// what keeps tp_sqlinjection.go a true positive.
func TestGoConcatenatedQueryTaintsArgZero(t *testing.T) {
	src := "package p\nimport \"database/sql\"\nfunc f(db *sql.DB, id string) { db.Query(\"SELECT x FROM t WHERE id = '\" + id + \"'\") }\n"
	_, firstTainted, _ := sinkArgsFor(t, src, "db.Query")
	if !firstTainted {
		t.Error("a concatenated query did not record the taint in the query string")
	}
}
