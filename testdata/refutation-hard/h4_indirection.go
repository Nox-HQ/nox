// Unsupported semantics. The value passes through a map and a closure stored in
// it, so the callee is a value rather than a name.
package hard

import (
	"net/http"
	"os/exec"
)

var table = map[string]func(string) error{
	"run": func(s string) error { return exec.Command("sh", "-c", s).Run() },
}

func Indirection(r *http.Request) error {
	cmd := r.URL.Query().Get("cmd")
	if fn, ok := table[r.URL.Query().Get("op")]; ok {
		return fn(cmd)
	}
	return nil
}
