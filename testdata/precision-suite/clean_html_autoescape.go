// Safe HTML rendering: user-controlled data is rendered through html/template,
// which performs context-aware auto-escaping on every interpolation. Injected
// markup is escaped to entities, so no XSS is possible. A precise scanner fires
// nothing — this is a precision guardrail for the XSS-to-response sink. Zero
// findings expected.
package web

import (
	"html/template"
	"net/http"
)

// page is the auto-escaping template; {{.Name}} and {{.Bio}} are contextually
// escaped by html/template, so any HTML in the values is neutralized.
var page = template.Must(template.New("page").Parse(
	`<div class="user"><h1>{{.Name}}</h1><p>{{.Bio}}</p></div>`))

// render passes the raw request values straight into html/template. Because the
// values are plain strings (not template.HTML), the engine escapes them — safe.
func render(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Name string
		Bio  string
	}{
		Name: r.URL.Query().Get("name"),
		Bio:  r.FormValue("bio"),
	}
	_ = page.Execute(w, data)
}
