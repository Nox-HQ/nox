package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

// GetUser looks up a user by the id query parameter.
func GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

// Lookup runs a DNS lookup for the host query parameter.
func Lookup(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("nslookup", host).Output()
	w.Write(out)
}
