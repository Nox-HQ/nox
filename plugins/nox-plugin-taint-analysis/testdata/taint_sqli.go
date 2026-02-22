package testdata

import (
	"database/sql"
	"net/http"
)

func handleSearch(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db, _ := sql.Open("postgres", "")
	db.Exec("SELECT * FROM users WHERE id=" + id)
}
