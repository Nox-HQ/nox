// Unsafe deserialization: attacker-controlled bytes from the request body are
// decoded with encoding/gob into an arbitrary structure. gob decoding of
// untrusted input is a known RCE/DoS vector (CWE-502). A correct scanner fires
// TAINT-005. nox has no Go taint model yet, so this is an honest recall gap.
package session

import (
	"encoding/gob"
	"net/http"
)

// Envelope is the type attacker bytes are decoded into.
type Envelope struct {
	User string
	Data map[string]any
}

// restore decodes the raw request body straight into Go values — the vulnerability.
func restore(r *http.Request) (*Envelope, error) {
	var env Envelope
	if err := gob.NewDecoder(r.Body).Decode(&env); err != nil { // nox-expect: TAINT-005
		return nil, err
	}
	return &env, nil
}
