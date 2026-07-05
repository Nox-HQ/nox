// Hardcoded provider credentials in Go string literals. A correct scanner
// resolves each token to its canonical provider rule (the secrets analyzer is
// language-agnostic and already fires on Go). Values are the canonical example
// shapes, not live credentials.
package config

// Config carries the (deliberately hardcoded) service credentials.
type Config struct {
	AWSAccessKeyID string
	GitHubToken    string
	SlackBotToken  string
}

// Load returns a Config populated from string literals — the vulnerability.
func Load() Config {
	return Config{
		AWSAccessKeyID: "AKIAIOSFODNN7EXAMPLE",                                   // nox-expect: SEC-001 SEC-508
		GitHubToken:    "ghp_016C7f8e9d0A1b2C3d4E5f6G7h8I9j0K1l2M",               // nox-expect: SEC-003
		SlackBotToken:  "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", // nox-expect: SEC-023
	}
}
