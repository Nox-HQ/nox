// SSRF: an attacker-controlled URL flows into http.Get with no allowlist, so
// the server can be coerced into fetching internal metadata endpoints —
// CWE-918. A correct scanner fires TAINT-006. nox has no Go taint model yet,
// so this is an honest recall gap.
package proxy

import (
	"io"
	"net/http"
)

// fetch proxies whatever URL the caller supplies — the vulnerability.
func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target) // nox-expect: TAINT-006
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(w, resp.Body)
}
