// Reflected XSS: an attacker-controlled request value is written into an HTTP
// response as HTML without escaping, so injected markup executes in the
// victim's browser — CWE-79. A correct scanner fires TAINT-003 (the taint
// engine's xss vuln_class, the same rule the Python/JS XSS samples annotate).
//
// This is distinct from the SSTI sink (tp_ssti.go): here the sink is the
// http.ResponseWriter itself, reached via fmt.Fprintf, w.Write, and the
// template.HTML() auto-escape bypass — three idiomatic ways Go reflects
// untrusted input into an HTML response.
package web

import (
	"fmt"
	"html/template"
	"net/http"
)

// greetPrintf reflects the raw query value into the HTML body via fmt.Fprintf —
// the classic reflected-XSS sink. The %s interpolation performs no escaping.
func greetPrintf(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<div>Hello, %s</div>", name) // nox-expect: TAINT-003
}

// greetWrite concatenates the form value into an HTML fragment and writes the
// raw bytes to the response — no escaping, so markup in the input executes.
func greetWrite(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_, _ = w.Write([]byte("<b>" + user + "</b>")) // nox-expect: TAINT-003
}

// greetAutoescapeBypass renders through html/template but launders the
// untrusted value through template.HTML(), which tells the engine the string
// is already-safe HTML and skips contextual escaping — the documented
// auto-escape escape hatch, and a reflected-XSS sink.
func greetAutoescapeBypass(w http.ResponseWriter, r *http.Request) {
	comment := r.URL.Query().Get("comment")
	t := template.Must(template.New("c").Parse(`<p>{{.}}</p>`))
	_ = t.Execute(w, template.HTML(comment)) // nox-expect: TAINT-003
}
