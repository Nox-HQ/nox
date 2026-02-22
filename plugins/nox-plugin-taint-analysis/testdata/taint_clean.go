package testdata

import (
	"database/sql"
	"net/http"
)

func handleSafeSearch(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db, _ := sql.Open("postgres", "")
	// Parameterized query — not vulnerable.
	db.Exec("SELECT * FROM users WHERE id=$1", id)
}
