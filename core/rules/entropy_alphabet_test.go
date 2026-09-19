package rules

import "testing"

// Character-set definitions are high-entropy by construction and never
// secrets. SEC-161 reported nox's own base62 alphabet (checksum.go) as one.
func TestAlphabetDefinitionsAreNotSecrets(t *testing.T) {
	t.Parallel()

	alphabets := map[string]string{
		"base62":      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"base64":      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		"base64url":   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		"base58":      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
		"base32":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		"crockford32": "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
	}
	for name, a := range alphabets {
		if !isLikelyNotSecret(a) {
			t.Errorf("%s alphabet is still treated as a possible secret", name)
		}
	}
}

// The recall half, and the reason a single consecutive run is not the test:
// human-chosen secrets contain runs. Every one of these must stay reportable.
func TestCredentialsWithRunsAreNotMistakenForAlphabets(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"deadbeef12345678",                         // existing hex fixture
		"Summer12345678!",                          // human password with a digit run
		"Pr0duction-12345678-ABCDEFGH-key",         // runs, but not an alphabet
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // AWS documented example
		"ghp_R8mQ2xVn4LkP7sT1wY9zB3cF6hJ0dA5eG2iK", // GitHub PAT shape
		"a9F3kQ7mZ2xV8pL4tR1wY6sB0cN5hJ3gD7eU",     // generic random
	} {
		if isCharacterSetDefinition(s) {
			t.Errorf("%q was classified as a character-set definition", s)
		}
	}
}
