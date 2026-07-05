package ai

import (
	"regexp"
	"strings"
)

// immutableRevisionRe matches a git-style commit SHA (7–64 hex chars). A model
// revision that is a bare tag/branch ("main", "v1.0") is mutable; a commit hash
// pins the exact weights.
var immutableRevisionRe = regexp.MustCompile(`^[a-fA-F0-9]{7,64}$`)

// isImmutableRevision reports whether a model revision string is a commit-hash
// pin (reproducible) rather than a mutable tag/branch.
func isImmutableRevision(revision string) bool {
	return immutableRevisionRe.MatchString(strings.TrimSpace(revision))
}

// classifyModelLicense returns the best-known license for a referenced model,
// keyed off its family. This is a deterministic, offline lookup — the AIBOM's
// answer to "what are we actually allowed to do with this model?", which a
// dependency SBOM never captures for models pulled by name. It is intentionally
// conservative: an unrecognized model returns "" (omitted from output) rather
// than a guessed license, so a present license field is trustworthy.
//
// Licenses reflect the model family's published terms at time of writing;
// downstream consumers should still verify against the model card for the exact
// checkpoint. Proprietary API models carry a "Proprietary (<vendor>)" marker so
// governance tooling can flag "no redistribution / API-terms apply".
func classifyModelLicense(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	// Strip a HuggingFace org prefix ("meta-llama/Llama-3-8B" -> "llama-3-8b").
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	switch {
	// Proprietary API models — no weights, vendor terms apply.
	case strings.HasPrefix(n, "gpt-"), strings.HasPrefix(n, "o1-"), strings.HasPrefix(n, "o3-"),
		strings.HasPrefix(n, "o4-"), strings.HasPrefix(n, "text-embedding-"), strings.HasPrefix(n, "dall-e"):
		return "Proprietary (OpenAI)"
	case strings.HasPrefix(n, "claude"):
		return "Proprietary (Anthropic)"
	case strings.HasPrefix(n, "gemini"):
		return "Proprietary (Google)"
	case strings.HasPrefix(n, "command"), strings.HasPrefix(n, "cohere"):
		return "Proprietary (Cohere)"

	// Open / source-available weights.
	case strings.HasPrefix(n, "llama"), strings.HasPrefix(n, "meta-llama"), strings.HasPrefix(n, "codellama"):
		return "Llama Community License"
	case strings.HasPrefix(n, "gemma"):
		return "Gemma Terms of Use"
	case strings.HasPrefix(n, "mistral"), strings.HasPrefix(n, "mixtral"), strings.HasPrefix(n, "ministral"):
		return "Apache-2.0"
	case strings.HasPrefix(n, "falcon"):
		return "Apache-2.0"
	case strings.HasPrefix(n, "phi-"), n == "phi":
		return "MIT"
	case strings.HasPrefix(n, "qwen"):
		return "Tongyi Qianwen License"
	case strings.HasPrefix(n, "deepseek"):
		return "DeepSeek License"
	case strings.HasPrefix(n, "stable-diffusion"), strings.HasPrefix(n, "sdxl"), strings.HasPrefix(n, "stabilityai"):
		return "CreativeML Open RAIL-M"
	case strings.HasPrefix(n, "bert"), strings.HasPrefix(n, "distilbert"), strings.HasPrefix(n, "roberta"),
		strings.HasPrefix(n, "t5"), strings.HasPrefix(n, "gpt2"), strings.HasPrefix(n, "bart"),
		strings.HasPrefix(n, "all-minilm"), strings.HasPrefix(n, "sentence-transformers"):
		return "Apache-2.0"
	}
	return ""
}
