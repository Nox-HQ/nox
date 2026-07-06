// Safe struct-field flow: an attacker-controlled request value is sanitized
// before it is stored in a struct field, and only the sanitized field reaches
// the sink. strconv.Atoi coerces the value to an int (a recognized sanitizer
// that strips injection metacharacters) and filepath.Clean+Base canonicalizes
// the path field, so no injection or traversal is possible. A precise scanner
// fires nothing — this is a precision guardrail for field-sensitive taint.
// Zero findings expected.
package job

import (
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Ticket carries only already-sanitized values through its fields.
type Ticket struct {
	Count int
	Path  string
}

// build validates and coerces the request values BEFORE storing them in the
// struct, so the fields are clean by construction.
func build(r *http.Request) Ticket {
	count, err := strconv.Atoi(r.FormValue("count"))
	if err != nil {
		count = 0
	}
	// filepath.Base drops any directory components; the result cannot traverse.
	safePath := filepath.Base(filepath.Clean(r.URL.Query().Get("path")))
	return Ticket{Count: count, Path: safePath}
}

// process reads the sanitized fields into the sinks — the int is formatted as a
// decimal (no metacharacters) and the path is already a bare filename.
func process(w http.ResponseWriter, r *http.Request) {
	t := build(r)
	out, _ := exec.Command("gen", "--count", strconv.Itoa(t.Count), "--file", t.Path).Output()
	_, _ = fmt.Fprintf(w, "generated %d records into %s\n%s", t.Count, t.Path, out)
}
