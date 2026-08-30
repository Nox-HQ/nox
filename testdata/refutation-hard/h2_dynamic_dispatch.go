// Dynamic dispatch. One implementation sanitizes, one does not, and the choice
// comes from data. Following only the statically-visible implementation sees a
// clean path that is not necessarily the one that runs.
package hard

import (
	"net/http"
	"os/exec"
)

type handler interface{ handle(string) error }

type quoted struct{}

func (quoted) handle(s string) error { return exec.Command("echo", s).Run() }

type raw struct{}

func (raw) handle(s string) error { return exec.Command("sh", "-c", s).Run() }

func Dispatch(r *http.Request) error {
	cmd := r.URL.Query().Get("cmd")
	var h handler = quoted{}
	if r.URL.Query().Get("mode") == "legacy" {
		h = raw{}
	}
	return h.handle(cmd)
}
