// Bounded analysis. The tainted value only reaches the sink after the eighth
// iteration, so an analysis that unrolls to a small bound sees a clean pass.
package hard

import (
	"net/http"
	"os/exec"
)

func BoundedLoop(r *http.Request) error {
	inputs := r.URL.Query()["arg"]
	cmd := "echo hello"
	for i := 0; i < len(inputs); i++ {
		if i > 8 {
			cmd = inputs[i]
		}
	}
	return exec.Command("sh", "-c", cmd).Run()
}
