// Guards: same-line and nearby sanitizer recognition (Track E / taint).
//
// Recognising a sanitizer is how a taint engine avoids reporting code that is
// already safe, and the triage-agent history shows why it is tempting to do it
// cheaply: its guards looked for a sanitizer near the match.
//
// Proximity is not dataflow. This handler escapes one value and writes
// another. html.EscapeString appears one line above the sink, the escaped
// result is even interpolated into the same response — and the injected value
// is a different variable that was never escaped at all. Any refuter that
// answers "is there a sanitizer around here?" instead of "was THIS value
// sanitized?" reports this file as clean.
package sample

import (
	"html"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	title := html.EscapeString(r.URL.Query().Get("title"))
	body := r.URL.Query().Get("body")
	_, _ = w.Write([]byte("<h1>" + title + "</h1><div>" + body + "</div>")) // nox-expect: TAINT-003
}
