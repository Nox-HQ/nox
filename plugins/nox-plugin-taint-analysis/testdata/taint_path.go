package testdata

import (
	"net/http"
	"os"
)

func handleFile(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("f")
	data, _ := os.ReadFile(file)
	w.Write(data)
}
