// Package discovery provides workspace artifact discovery and classification.
//
// It recursively walks a project directory, classifies files by type (source
// code, configuration, lockfiles, container definitions, AI components), and
// returns a sorted inventory of discovered artifacts. Gitignore patterns are
// respected and the .git directory is always skipped.
package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ArtifactType identifies the category of a discovered file.
type ArtifactType string

const (
	// Source represents programming language source files.
	Source ArtifactType = "source"
	// Config represents configuration files.
	Config ArtifactType = "config"
	// Lockfile represents dependency lock files.
	Lockfile ArtifactType = "lockfile"
	// Container represents container-related files (Dockerfile, compose).
	Container ArtifactType = "container"
	// AIComponent represents AI/LLM-related artifacts (prompts, agents, MCP).
	AIComponent ArtifactType = "ai_component"
	// Unknown represents files that do not match any known category.
	Unknown ArtifactType = "unknown"
)

// Artifact represents a single discovered file in the workspace.
type Artifact struct {
	// Path is the file path relative to the walker root.
	Path string
	// AbsPath is the absolute file path.
	AbsPath string
	// Type is the classified artifact type.
	Type ArtifactType
	// Size is the file size in bytes.
	Size int64
}

// Classifier determines the ArtifactType of a file based on its path and
// metadata. Implementations should return Unknown when they cannot classify
// the file so that subsequent classifiers in a registry may attempt it.
type Classifier interface {
	Classify(path string, info os.FileInfo) ArtifactType
}

// ClassifierRegistry holds an ordered list of Classifiers. When classifying a
// file it calls each classifier in order and returns the first non-Unknown
// result. If no classifier matches, Unknown is returned.
type ClassifierRegistry struct {
	classifiers []Classifier
}

// NewClassifierRegistry creates an empty ClassifierRegistry.
func NewClassifierRegistry() *ClassifierRegistry {
	return &ClassifierRegistry{}
}

// Register appends a classifier to the registry.
func (r *ClassifierRegistry) Register(c Classifier) {
	r.classifiers = append(r.classifiers, c)
}

// Classify iterates through registered classifiers and returns the first
// non-Unknown result.
func (r *ClassifierRegistry) Classify(path string, info os.FileInfo) ArtifactType {
	for _, c := range r.classifiers {
		if t := c.Classify(path, info); t != Unknown {
			return t
		}
	}
	return Unknown
}

// DefaultClassifier classifies files by extension and well-known names.
type DefaultClassifier struct{}

// lockfileNames contains exact file names that identify lockfiles.
var lockfileNames = map[string]bool{
	"package-lock.json": true,
	"go.sum":            true,
	"yarn.lock":         true,
	"poetry.lock":       true,
	"Gemfile.lock":      true,
	"Cargo.lock":        true,
	"pnpm-lock.yaml":    true,
	"requirements.txt":  true,
}

// containerNames contains exact file names that identify container files.
var containerNames = map[string]bool{
	"Dockerfile":          true,
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
}

// sourceExtensions maps file extensions to the Source artifact type.
var sourceExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".rb":   true,
	".java": true,
	".rs":   true,
	".c":    true,
	".cpp":  true,
	".h":    true,
	".cs":   true,
	".sh":   true,
}

// configExtensions maps file extensions to the Config artifact type.
var configExtensions = map[string]bool{
	".yaml":   true,
	".yml":    true,
	".toml":   true,
	".json":   true,
	".ini":    true,
	".cfg":    true,
	".conf":   true,
	".tf":     true,
	".tfvars": true,
}

// Classify determines the ArtifactType of a file using extension and name
// matching. Classification priority: Lockfile > Container > AIComponent >
// Config > Source > Unknown.
func (d *DefaultClassifier) Classify(path string, _ os.FileInfo) ArtifactType {
	name := filepath.Base(path)
	ext := filepath.Ext(name)
	normalised := filepath.ToSlash(path)

	// Lockfiles by exact name.
	if lockfileNames[name] {
		return Lockfile
	}

	// Container files by exact name.
	if containerNames[name] {
		return Container
	}

	// Container files by extension pattern (*.dockerfile).
	if ext == ".dockerfile" {
		return Container
	}

	// AI components: specific names and path patterns.
	if isAIComponent(name, normalised) {
		return AIComponent
	}

	// Config by extension. Also catch .env files by prefix.
	if configExtensions[ext] {
		return Config
	}
	if strings.HasPrefix(name, ".env") {
		return Config
	}

	// Source by extension.
	if sourceExtensions[ext] {
		return Source
	}

	return Unknown
}

// isAIComponent returns true when a file name or path matches AI component
// patterns: mcp.json, *.prompt, *.prompt.md, or paths containing /prompts/
// or /agents/ segments.
func isAIComponent(name, normalised string) bool {
	if name == "mcp.json" {
		return true
	}
	if strings.HasSuffix(name, ".prompt") {
		return true
	}
	if strings.HasSuffix(name, ".prompt.md") {
		return true
	}
	if containsSegment(normalised, "prompts") || containsSegment(normalised, "agents") {
		return true
	}
	return false
}

// containsSegment reports whether the slash-separated path contains the given
// directory segment.
func containsSegment(path, segment string) bool {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p == segment {
			return true
		}
	}
	return false
}

// Walker recursively discovers and classifies files under Root.
type Walker struct {
	// Root is the directory to walk.
	Root string
	// Registry classifies discovered files.
	Registry *ClassifierRegistry
	// IgnorePatterns holds gitignore-style patterns for skipping files.
	IgnorePatterns []string
}

// NewWalker creates a Walker rooted at root with the DefaultClassifier
// registered. It attempts to load .gitignore patterns from the root directory;
// if no .gitignore exists the walker proceeds with no ignore patterns.
func NewWalker(root string) *Walker {
	reg := NewClassifierRegistry()
	reg.Register(&DefaultClassifier{})

	patterns, _ := LoadGitignore(root)

	return &Walker{
		Root:           root,
		Registry:       reg,
		IgnorePatterns: patterns,
	}
}

// Walk recursively traverses the Root directory, classifies each regular file,
// and returns the collected artifacts sorted by relative path. Directories
// matching ignore patterns or named .git are skipped entirely.
func (w *Walker) Walk() ([]Artifact, error) {
	absRoot, err := filepath.Abs(w.Root)
	if err != nil {
		return nil, err
	}

	var artifacts []Artifact

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Compute the path relative to root.
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}

		// Skip the root itself.
		if rel == "." {
			return nil
		}

		// Always skip .git directories.
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		// Check gitignore patterns.
		if IsIgnored(rel, w.IgnorePatterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Only classify regular files.
		if !info.Mode().IsRegular() {
			return nil
		}

		artifactType := w.Registry.Classify(rel, info)

		artifacts = append(artifacts, Artifact{
			Path:    filepath.ToSlash(rel),
			AbsPath: path,
			Type:    artifactType,
			Size:    info.Size(),
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Path < artifacts[j].Path
	})

	return artifacts, nil
}
