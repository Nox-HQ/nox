package ai

import (
	"regexp"
	"strings"
)

// ModelReference represents a reference to an ML model found in the codebase.
type ModelReference struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Registry string `json:"registry,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Path     string `json:"path"`
}

// extractModelReferences scans file content for ML model loading patterns and
// returns discovered model references.
func extractModelReferences(path string, content []byte) []ModelReference {
	var refs []ModelReference
	text := string(content)

	// Pattern: from_pretrained("model-name") or from_pretrained('model-name', revision="...")
	fromPretrainedRe := regexp.MustCompile(`(?i)(?:from_pretrained|AutoModel\w*|pipeline)\s*\(\s*['"]([^'"]+)['"]`)
	matches := fromPretrainedRe.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		ref := ModelReference{
			Name: m[1],
			Path: path,
		}
		// Detect registry from model name
		ref.Registry = classifyModelRegistry(m[1])
		// Look for revision/hash on same line
		ref.Version = extractModelVersion(text, m[0])
		ref.Hash = extractModelHash(text, m[0])
		refs = append(refs, ref)
	}

	// Pattern: model: "name" or model = "name" in YAML/config
	modelConfigRe := regexp.MustCompile(`(?i)(?:model|model_name|model_id)\s*[:=]\s*['"]([^'"]+)['"]`)
	configMatches := modelConfigRe.FindAllStringSubmatch(text, -1)
	for _, m := range configMatches {
		// Skip if already found via from_pretrained
		if containsModel(refs, m[1]) {
			continue
		}
		refs = append(refs, ModelReference{
			Name:     m[1],
			Registry: classifyModelRegistry(m[1]),
			Path:     path,
		})
	}

	return refs
}

func classifyModelRegistry(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "huggingface.co") || strings.Contains(name, "/"):
		return "huggingface"
	case strings.HasPrefix(lower, "gpt-") || strings.HasPrefix(lower, "o1-") || strings.HasPrefix(lower, "o3-"):
		return "openai"
	case strings.HasPrefix(lower, "claude"):
		return "anthropic"
	case strings.HasPrefix(lower, "gemini"):
		return "google"
	case strings.HasPrefix(lower, "llama") || strings.HasPrefix(lower, "meta-llama"):
		return "meta"
	case strings.HasPrefix(lower, "mistral") || strings.HasPrefix(lower, "mixtral"):
		return "mistral"
	case strings.Contains(lower, "ollama"):
		return "ollama"
	default:
		return "unknown"
	}
}

func extractModelVersion(text, context string) string {
	// Look near context for revision= or version=
	re := regexp.MustCompile(`(?i)revision\s*=\s*['"]([^'"]+)['"]`)
	idx := strings.Index(text, context)
	if idx >= 0 {
		// Search within 200 chars after the match
		end := idx + len(context) + 200
		if end > len(text) {
			end = len(text)
		}
		if m := re.FindStringSubmatch(text[idx:end]); m != nil {
			return m[1]
		}
	}
	return ""
}

func extractModelHash(text, context string) string {
	re := regexp.MustCompile(`(?i)(?:sha256|hash)\s*[:=]\s*['"]([a-f0-9]{40,64})['"]`)
	idx := strings.Index(text, context)
	if idx >= 0 {
		end := idx + len(context) + 300
		if end > len(text) {
			end = len(text)
		}
		if m := re.FindStringSubmatch(text[idx:end]); m != nil {
			return m[1]
		}
	}
	return ""
}

func containsModel(refs []ModelReference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}
