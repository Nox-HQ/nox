// Container-sensitive taint: an attacker-controlled request value is written
// into a map value (and a slice element), then read back out of the container
// and passed to a command sink. The taint must propagate through the container
// element to reach the sink — CWE-78. A correct scanner fires TAINT-002.
//
// nox's Go taint engine is variable-level (AST-only, no container element
// tracking), so the flow through m["c"] / args[0] is expected to be a false
// negative until container sensitivity lands. The annotation is ground truth.
package job

import (
	"net/http"
	"os/exec"
)

// runMap stashes the request value into a map, then reads it back into the
// shell command — the taint flows through the map value m["c"].
func runMap(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("c")
	m := map[string]string{}
	m["c"] = user
	out, _ := exec.Command("sh", "-c", m["c"]).Output() // nox-expect: TAINT-002
	_, _ = w.Write(out)
}

// runSlice stashes the request value into a slice element, then reads it back
// into the shell command — the taint flows through the slice element args[0].
func runSlice(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("c")
	args := []string{user}
	out, _ := exec.Command("sh", "-c", args[0]).Output() // nox-expect: TAINT-002
	_, _ = w.Write(out)
}
