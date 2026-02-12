package ai

import (
	"regexp"
	"strings"
)

// TrustedRegistries lists known legitimate model registries. These are used by
// IsUntrustedRegistry to decide whether a model download URL points to a
// reputable source.
var TrustedRegistries = []string{
	"huggingface.co",
	"hf.co",
	"pytorch.org",
	"tfhub.dev",
	"kaggle.com",
	"registry.ollama.ai",
	"models.ai.azure.com",
}

// IsUntrustedRegistry returns true if the URL does not match any of the known
// trusted model registries listed in TrustedRegistries. An empty URL is
// considered untrusted.
func IsUntrustedRegistry(url string) bool {
	lower := strings.ToLower(url)
	for _, registry := range TrustedRegistries {
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
