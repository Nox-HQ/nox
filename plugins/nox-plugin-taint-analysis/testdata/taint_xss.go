package testdata

import (
	"html/template"
	"net/http"
)

func handleGreet(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	unsafe := template.HTML(name)
	_ = unsafe
}
