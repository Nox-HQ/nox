// Server-side template injection: a request-controlled string is parsed as a
// text/template and executed, letting an attacker inject template actions —
// CWE-1336 / CWE-94. A correct scanner fires TAINT-003 (the taint engine's
// SSTI sink). Unlike the Python SSTI sample (caught by the VARIANT-005 CVE
// signature), nox has no Go variant signature and no Go taint model, so this
// is an honest recall gap.
package render

import (
	"net/http"
	"text/template"
)

// greet parses a caller-supplied template string, then executes it — the vulnerability.
func greet(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("tmpl")
	tmpl, err := template.New("greeting").Parse(src) // nox-expect: TAINT-003
	if err != nil {
		http.Error(w, "bad template", http.StatusBadRequest)
		return
	}
	_ = tmpl.Execute(w, map[string]string{"name": "world"})
}
