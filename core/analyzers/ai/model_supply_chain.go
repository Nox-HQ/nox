package ai

import (
	"regexp"
	"strings"
)

// trustedRegistries lists known legitimate model registries. Kept unexported
// and immutable; expose a defensive copy via TrustedRegistries().
var trustedRegistries = []string{
	"huggingface.co",
	"hf.co",
	"pytorch.org",
	"tfhub.dev",
	"kaggle.com",
	"registry.ollama.ai",
	"models.ai.azure.com",
}

// TrustedRegistries returns a copy of the known legitimate model registries.
// Returning a copy prevents callers from mutating the package's trust list.
func TrustedRegistries() []string {
	return append([]string(nil), trustedRegistries...)
}

// IsUntrustedRegistry returns true if the URL does not match any of the known
// trusted model registries. An empty URL is considered untrusted.
func IsUntrustedRegistry(url string) bool {
	lower := strings.ToLower(url)
	for _, registry := range trustedRegistries {
		if strings.Contains(lower, registry) {
			return false
		}
	}
	return true
}

// hashPinPattern matches common hash pin formats used for model integrity
// verification: sha256:, sha1:, md5:, blake2b:, or a bare hex string of at
// least 64 characters (typical sha256 digest).
var hashPinPattern = regexp.MustCompile(`(?i)(sha256:|sha1:|md5:|blake2b:)[0-9a-f]+`)

// HasHashPin returns true if the reference string contains a hash pin such as
// "sha256:abc123..." or "md5:def456...". This is used to determine whether a
// model reference includes integrity verification.
func HasHashPin(reference string) bool {
	return hashPinPattern.MatchString(reference)
}
