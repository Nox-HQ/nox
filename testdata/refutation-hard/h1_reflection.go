// Reflection. The same source and sink as a case nox detects, with the call
// made through reflect so nothing static resolves the callee.
//
// The correct answer is UNDETERMINED. Dropping the finding here would state a
// negative the analysis has not earned.
package hard

import (
	"net/http"
	"os/exec"
	"reflect"
)

type runner struct{}

func (runner) Run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func Reflection(r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	m := reflect.ValueOf(runner{}).MethodByName("Run")
	m.Call([]reflect.Value{reflect.ValueOf(cmd)})
}
