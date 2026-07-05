// Example / placeholder configuration and env-sourced secrets — no real
// credentials. The placeholder allowlist and "read from env" idiom must keep
// this clean: zero findings.
package config

import "os"

// Defaults documents the expected environment variables with placeholder values.
const (
	exampleAPIKey   = "your-api-key-here"
	examplePassword = "changeme"
	exampleToken    = "xxxxxxxxxxxxxxxxxxxxxxxx"
	exampleDBURL    = "postgres://USER:PASSWORD@localhost:5432/db"
)

// FromEnv reads the real credentials from the environment at runtime — the
// correct pattern, with nothing hardcoded.
func FromEnv() (apiKey, dbURL string) {
	apiKey = os.Getenv("API_KEY")
	dbURL = os.Getenv("DATABASE_URL")
	return apiKey, dbURL
}
