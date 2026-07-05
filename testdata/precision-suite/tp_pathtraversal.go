// Path traversal: a request-controlled filename flows into os.ReadFile via
// filepath.Join with no containment check, so "../../etc/passwd" escapes the
// base directory — CWE-22. A correct scanner fires TAINT-004. nox has no Go
// taint model yet, so this is an honest recall gap.
package files

import (
	"net/http"
	"os"
	"path/filepath"
)

// serveDownload reads whatever path the caller names — the vulnerability.
func serveDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(filepath.Join("/srv/downloads", name)) // nox-expect: TAINT-004
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}
