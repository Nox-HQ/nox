// Safe database and command idioms in Go — every one is the correct, guarded
// form, so a precise scanner fires nothing. Zero findings expected.
package store

import (
	"database/sql"
	"os/exec"
)

// lookup uses a parameterized query ($1 placeholder) — the driver binds the
// value, so no injection is possible.
func lookup(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT name, email FROM users WHERE id = $1", id)
}

// listDir runs a fixed argument vector (no shell), with the user value passed
// as a distinct argument rather than interpolated into a command string.
func listDir(dir string) ([]byte, error) {
	return exec.Command("ls", "-la", "--", dir).Output()
}

// allowedRegions is a fixed allowlist; only values it contains reach the callee.
var allowedRegions = map[string]bool{"us-east-1": true, "eu-west-1": true}

// region validates input against the allowlist before use.
func region(candidate string) string {
	if allowedRegions[candidate] {
		return candidate
	}
	return "us-east-1"
}
