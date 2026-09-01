// Safe database and command idioms in Go — every one is the correct, guarded
// form, so a precise scanner fires nothing. Zero findings expected.
//
// The values come from an http.Request, a real taint SOURCE. That is
// load-bearing: this file previously took its values as function PARAMETERS, so
// nothing flowed into these calls and the sample stayed clean whether the
// parameterized-query and arg-vector refinements worked, broke, or were
// deleted. A clean sample with no source proves nothing — it reads like a guard
// and is inert.
package store

import (
	"database/sql"
	"net/http"
	"os/exec"
)

// lookup uses a parameterized query ($1 placeholder) — the driver binds the
// value, so no injection is possible.
func lookup(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	id := r.URL.Query().Get("id")
	return db.Query("SELECT name, email FROM users WHERE id = $1", id)
}

// listDir runs a fixed argument vector (no shell), with the user value passed
// as a distinct argument rather than interpolated into a command string.
func listDir(r *http.Request) ([]byte, error) {
	dir := r.URL.Query().Get("dir")
	return exec.Command("ls", "-la", "--", dir).Output()
}

// allowedRegions is a fixed allowlist; only values it contains reach the callee.
var allowedRegions = map[string]bool{"us-east-1": true, "eu-west-1": true}

// region validates input against the allowlist before use.
func region(r *http.Request) string {
	candidate := r.URL.Query().Get("region")
	if allowedRegions[candidate] {
		return candidate
	}
	return "us-east-1"
}
