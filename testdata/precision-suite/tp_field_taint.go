// Field-sensitive taint: an attacker-controlled request value is stored in a
// struct field, then the field is read back and passed to a command sink. The
// taint must propagate through the struct field to reach the sink — CWE-78.
// A correct scanner fires TAINT-002.
//
// nox's Go taint engine is variable-level (AST-only, no field sensitivity), so
// the flow through Cmd.Arg is expected to be a false negative until field
// sensitivity lands. The annotation is the ground truth a correct scanner meets.
package job

import (
	"net/http"
	"os/exec"
)

// Cmd carries the command argument through a struct field between source and sink.
type Cmd struct {
	Arg string
}

// run reads a request parameter, stashes it in a struct field, then reads that
// field back into a shell invocation — the vulnerability flows through Cmd.Arg.
func run(w http.ResponseWriter, r *http.Request) {
	req := Cmd{Arg: r.FormValue("c")}
	out, _ := exec.Command("sh", "-c", req.Arg).Output() // nox-expect: TAINT-002
	_, _ = w.Write(out)
}
