// SQL injection: a request parameter is string-concatenated into a query
// passed to db.Query — CWE-89. A correct scanner fires TAINT-001. nox has no
// Go taint model yet, so this is an honest recall gap.
package store

import (
	"database/sql"
	"net/http"
)

// lookupUser builds a query by concatenating untrusted input — the vulnerability.
func lookupUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	id := r.URL.Query().Get("id")
	return db.Query("SELECT name, email FROM users WHERE id = '" + id + "'") // nox-expect: TAINT-001
}
