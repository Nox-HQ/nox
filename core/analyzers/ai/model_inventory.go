package ai

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/rules"
)

// ModelReference represents a reference to an ML model found in the codebase.
type ModelReference struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// License is the model family's known license (SPDX-ish or a
	// "Proprietary (<vendor>)" marker), from a curated offline lookup. Empty
	// when the family is unrecognized — a present value is trustworthy, not a
	// guess. This is the AIBOM's model-license/provenance answer that a
	// dependency SBOM misses for models pulled by name.
	License    string `json:"license,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Path       string `json:"path"`
	Line       int    `json:"line,omitempty"`
	AuthEnvVar string `json:"auth_env_var,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	// Pinned reports whether the reference is fixed to an immutable revision or
	// digest (a hash/commit pin), so the exact weights are reproducible — the
	// provenance signal for "which model did we actually run".
	Pinned bool `json:"pinned"`
}

// extractModelReferences scans file content for ML model loading patterns and
// returns discovered model references.
func extractModelReferences(path string, content []byte) []ModelReference {
	return extractModelReferencesIn(path, content, false)
}

// The model patterns are compiled once; the two run over whole files go
// through the literal-prefix plan, as the prompt patterns do.
var (
	modelFromPretrainedRe = rules.MustCompilePlanned(`(?i)(?:from_pretrained|AutoModel\w*|pipeline)\s*\(\s*['"]([^'"]+)['"]`)
	modelConfigRe         = rules.MustCompilePlanned(`(?i)(?:model|model_name|model_id)\s*[:=]\s*['"]([^'"]+)['"]`)
	modelRevisionRe       = regexp.MustCompile(`(?i)revision\s*=\s*['"]([^'"]+)['"]`)
	modelHashRe           = regexp.MustCompile(`(?i)(?:sha256|hash)\s*[:=]\s*['"]([a-f0-9]{40,64})['"]`)
)

// stringSubmatches turns FindAllSubmatchIndex results over text into what
// FindAllStringSubmatch returns: each group's text, "" for one that did not
// take part.
func stringSubmatches(text string, locs [][]int) [][]string {
	out := make([][]string, 0, len(locs))
	for _, loc := range locs {
		m := make([]string, len(loc)/2)
		for i := range m {
			if loc[2*i] >= 0 {
				m[i] = text[loc[2*i]:loc[2*i+1]]
			}
		}
		out = append(out, m)
	}
	return out
}

// extractModelReferencesIn is extractModelReferences with a precision switch
// for the config-style pattern. With requireKnownFamily set, a `model: "X"`
// assignment is a model reference only when X names a recognised model family
// (classifyModelRegistry is not "unknown"). The pattern alone cannot tell an
// LLM from an ORM model name, and in ordinary source nothing else vouches for
// it; from_pretrained and pipeline calls carry their own evidence and are
// always kept.
func extractModelReferencesIn(path string, content []byte, requireKnownFamily bool) []ModelReference {
	var refs []ModelReference
	text := string(content)

	// Pattern: from_pretrained("model-name") or from_pretrained('model-name', revision="...")
	for _, m := range stringSubmatches(text, modelFromPretrainedRe.FindAllSubmatchIndex(content)) {
		ref := ModelReference{
			Name: m[1],
			Path: path,
		}
		// Detect registry from model name
		ref.Registry = classifyModelRegistry(m[1])
		// Look for revision/hash on same line
		ref.Version = extractModelVersion(text, m[0])
		ref.Hash = extractModelHash(text, m[0])
		ref.License = classifyModelLicense(ref.Name)
		ref.Pinned = ref.Hash != "" || isImmutableRevision(ref.Version)
		refs = append(refs, ref)
	}

	// Pattern: model: "name" or model = "name" in YAML/config
	for _, m := range stringSubmatches(text, modelConfigRe.FindAllSubmatchIndex(content)) {
		// Skip if already found via from_pretrained
		if containsModel(refs, m[1]) {
			continue
		}
		registry := classifyModelRegistry(m[1])
		if requireKnownFamily && registry == "unknown" {
			continue
		}
		refs = append(refs, ModelReference{
			Name:     m[1],
			Registry: registry,
			License:  classifyModelLicense(m[1]),
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
	idx := strings.Index(text, context)
	if idx >= 0 {
		// Search within 200 chars after the match
		end := idx + len(context) + 200
		if end > len(text) {
			end = len(text)
		}
		if m := modelRevisionRe.FindStringSubmatch(text[idx:end]); m != nil {
			return m[1]
		}
	}
	return ""
}

func extractModelHash(text, context string) string {
	idx := strings.Index(text, context)
	if idx >= 0 {
		end := idx + len(context) + 300
		if end > len(text) {
			end = len(text)
		}
		if m := modelHashRe.FindStringSubmatch(text[idx:end]); m != nil {
			return m[1]
		}
	}
	return ""
}

func containsModel(refs []ModelReference, name string) bool {
	for i := range refs {
		if refs[i].Name == name {
			return true
		}
	}
	return false
}
