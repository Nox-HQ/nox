// Hardcoded provider credentials in Go string literals. A correct scanner
// resolves each token to its canonical provider rule (the secrets analyzer is
// language-agnostic and already fires on Go). Values are the canonical example
// shapes, not live credentials.
//
// The GitHub token carries a VALID embedded CRC32 checksum, for the same reason
// tp_secrets.py's does: a sample a correct scanner can deterministically refute
// is a poor true positive for "a hardcoded GitHub token". This one was missed
// when checksum verification landed and kept a random body until Track C3 went
// looking for subjects whose evidence contradicts itself. Until then nox
// reported it while its own strongest claim said it was not a credential.
//
// Synthetic and matching no issued credential; the body says so in plain text.
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
		GitHubToken:    "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",               // nox-expect: SEC-003
		SlackBotToken:  "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", // nox-expect: SEC-023
	}
}
