// Command injection: an attacker-controlled query parameter flows into a
// shell invocation via exec.Command("sh", "-c", ...) with no allowlist. This
// is CWE-78. A correct scanner fires TAINT-002; nox's taint catalog has no Go
// language entry yet (only python/javascript), so this is an honest recall gap
// — the annotation flips to a TP when a Go source/sink model lands.
package handler

import (
	"net/http"
	"os/exec"
)

// runReport shells out to a user-supplied command — the vulnerability.
func runReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("report")
	out, _ := exec.Command("sh", "-c", "generate-report "+name).Output() // nox-expect: TAINT-002
	_, _ = w.Write(out)
}
