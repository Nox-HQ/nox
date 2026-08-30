// Dynamic loading. The callee does not exist at analysis time, so "no sink
// found" is a statement about the code that was present.
package hard

import (
	"net/http"
	"plugin"
)

func DynamicLoad(r *http.Request, path string) error {
	cmd := r.URL.Query().Get("cmd")
	p, err := plugin.Open(path)
	if err != nil {
		return err
	}
	s, err := p.Lookup("Exec")
	if err != nil {
		return err
	}
	if fn, ok := s.(func(string) error); ok {
		return fn(cmd)
	}
	return nil
}
