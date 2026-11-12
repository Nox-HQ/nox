// Package testkey makes credential-shaped values for tests.
//
// A test that needs "a file with a secret in it" used to write the access key
// ID AWS prints in its own documentation. That value was never a credential, so
// a test asserting that a leaked credential is found, is high severity, or
// fails the build needs a value nobody has published, and one written by hand
// tends to be the kind of value a refiner correctly discards (a repeated
// character, a dictionary word).
//
// The values here are drawn from a seeded generator, so they have the shape and
// the entropy of the real thing, are the same on every run, and exist nowhere
// as a literal for a scanner (nox's own included) to find in this repository.
// None of them was ever issued.
package testkey

import "math/rand"

const (
	base32Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	base64Body  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
)

// AWSAccessKeyID returns a value shaped like a long-term AWS access key ID:
// AKIA and sixteen base32 characters.
func AWSAccessKeyID() string {
	return "AKIA" + body(1, base32Upper, 16)
}

// AWSSecretAccessKey returns a value shaped like an AWS secret access key:
// forty characters of the base64 alphabet.
func AWSSecretAccessKey() string {
	return body(2, base64Body, 40)
}

// body draws n characters of alphabet from a generator seeded with seed.
func body(seed int64, alphabet string, n int) string {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // a reproducible test value, not a secret
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}
