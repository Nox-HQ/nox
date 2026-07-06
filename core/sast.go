package core

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
)

// SASTDepth is a per-language SAST analysis depth level. The strategy is
// "depth where the moat is": invest deep analysis in the languages where AI
// apps and false-positive hotspots concentrate, standard pattern coverage
// elsewhere, and nothing for languages a repo doesn't care about.
type SASTDepth string

const (
	// SASTDeep marks a language for the deepest analysis nox can offer. Today
	// deep is behaviorally identical to standard (both run the pattern rules) —
	// it reserves a home for future AST/taint analysis without a config break.
	SASTDeep SASTDepth = "deep"
	// SASTStandard runs the current pattern-based rule analysis. It is the
	// default for every language not explicitly listed.
	SASTStandard SASTDepth = "standard"
	// SASTOff skips a language entirely: its source files contribute no
	// findings to the pattern analyzers. Use it for languages a repo does not
	// care to scan.
	SASTOff SASTDepth = "off"
)

// DefaultLanguageDepth is the depth applied to a language with no explicit
// entry in SASTConfig.Languages. Python/JS/TS default to deep (see
// deepByDefaultLanguages); everything else is standard.
func DefaultLanguageDepth(language string) SASTDepth {
	if deepByDefaultLanguages[language] {
		return SASTDeep
	}
	return SASTStandard
}

// deepByDefaultLanguages is the set of languages that default to deep analysis:
// Python and JavaScript/TypeScript. These are where AI applications are built
// and where the pattern rules produce the worst false positives, so they earn
// the deepest analysis and are the first targets for future AST/taint work.
var deepByDefaultLanguages = map[string]bool{
	"python":     true,
	"javascript": true,
	"typescript": true,
}

// validSASTDepths is the set of accepted depth strings, used by validation.
var validSASTDepths = map[SASTDepth]bool{
	SASTDeep:     true,
	SASTStandard: true,
	SASTOff:      true,
}

// extensionLanguages maps a source-file extension to its canonical language
// name for SAST-profile lookup. It mirrors discovery.sourceExtensions (the set
// of extensions classified as Source) so every scannable source file resolves
// to a language. Config/lockfile/container artifacts carry no source language
// and are never subject to the language profile.
var extensionLanguages = map[string]string{
	".go":    "go",
	".py":    "python",
	".js":    "javascript",
	".jsx":   "javascript",
	".mjs":   "javascript",
	".cjs":   "javascript",
	".ts":    "typescript",
	".tsx":   "typescript",
	".mts":   "typescript",
	".cts":   "typescript",
	".rb":    "ruby",
	".java":  "java",
	".kt":    "kotlin",
	".swift": "swift",
	".php":   "php",
	".rs":    "rust",
	".c":     "c",
	".cpp":   "cpp",
	".cc":    "cpp",
	".cxx":   "cpp",
	".c++":   "cpp",
	".h":     "c",
	".hpp":   "cpp",
	".hh":    "cpp",
	".hxx":   "cpp",
	".ipp":   "cpp",
	".inl":   "cpp",
	".cs":    "csharp",
	".sh":    "shell",
	// Objective-C / Objective-C++ implementation files (headers stay C/C++).
	".m":  "objc",
	".mm": "objc",
}

// LanguageForExtension returns the canonical language name for a file path
// based on its extension, or "" when the extension maps to no known source
// language. The lookup is case-insensitive on the extension.
func LanguageForExtension(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return extensionLanguages[ext]
}

// ResolveDepth returns the effective SAST depth for a canonical language name,
// applying the explicit config entry when present and DefaultLanguageDepth
// otherwise. Language names are matched case-insensitively so `Python` and
// `python` resolve the same. An empty or unknown-depth entry is treated as
// absent (defaulting), since Validate rejects unknown depths before a scan.
func (c SASTConfig) ResolveDepth(language string) SASTDepth {
	if language == "" {
		return SASTStandard
	}
	lang := strings.ToLower(language)
	if raw, ok := c.lookup(lang); ok {
		d := SASTDepth(strings.ToLower(raw))
		if validSASTDepths[d] {
			return d
		}
	}
	return DefaultLanguageDepth(lang)
}

// lookup finds a configured depth for a language, matching keys
// case-insensitively so config authors can write `Python` or `python`.
func (c SASTConfig) lookup(lang string) (string, bool) {
	if c.Languages == nil {
		return "", false
	}
	if v, ok := c.Languages[lang]; ok {
		return v, true
	}
	for k, v := range c.Languages {
		if strings.EqualFold(k, lang) {
			return v, true
		}
	}
	return "", false
}

// Validate rejects unknown depth values so a typo (e.g. `depe`) fails the scan
// loudly at config load instead of silently defaulting. Language names are not
// validated — an unknown language simply never matches a source file — but its
// depth string still must be one of deep|standard|off.
func (c SASTConfig) Validate() error {
	// Sort keys so the error message is deterministic across runs.
	langs := make([]string, 0, len(c.Languages))
	for lang := range c.Languages {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	for _, lang := range langs {
		d := SASTDepth(strings.ToLower(c.Languages[lang]))
		if !validSASTDepths[d] {
			return fmt.Errorf("scan.sast.languages: invalid depth %q for %q (want deep|standard|off)", c.Languages[lang], lang)
		}
	}
	return nil
}

// ResolvedProfile returns the effective depth for every language nox knows how
// to classify, merged with any explicitly configured entries (including
// languages nox has no extension mapping for, which a config may still list).
// The result is the auditable record written to the report meta — it answers
// "what depth did this scan apply to each language?" without the reader having
// to re-derive defaults. Keys are canonical, lowercased language names; values
// are the string form of the resolved depth.
func (c SASTConfig) ResolvedProfile() map[string]string {
	profile := make(map[string]string)
	for _, lang := range extensionLanguages {
		profile[lang] = string(c.ResolveDepth(lang))
	}
	for lang := range c.Languages {
		l := strings.ToLower(lang)
		profile[l] = string(c.ResolveDepth(l))
	}
	return profile
}

// FilterArtifactsByLanguageProfile drops source artifacts whose resolved SAST
// depth is "off" so they reach no pattern analyzer and contribute no findings.
// Non-source artifacts (config, lockfiles, containers, AI components) carry no
// source language and always pass through — turning off a language must not
// silence dependency, IaC, or secret scanning of unrelated files. Source files
// whose extension maps to no known language also pass through (they cannot be
// addressed by the language profile). The input order is preserved so the scan
// stays deterministic.
func FilterArtifactsByLanguageProfile(artifacts []discovery.Artifact, cfg SASTConfig) []discovery.Artifact {
	filtered := make([]discovery.Artifact, 0, len(artifacts))
	for _, a := range artifacts {
		if a.Type == discovery.Source {
			if lang := LanguageForExtension(a.Path); lang != "" && cfg.ResolveDepth(lang) == SASTOff {
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered
}
