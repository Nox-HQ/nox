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

// LockfileNames returns the set of filenames that discovery classifies as
// dependency lockfiles.
//
// Exported so the dependency analyzer can assert that every classified
// lockfile is either parsed or explicitly known to be redundant. Adding a name
// here without a parser creates a silent blind spot — a project of that
// ecosystem scans clean while nothing was read — which is exactly what
// happened to yarn, pnpm and poetry.
func LockfileNames() []string {
	out := make([]string, 0, len(lockfileNames))
	for name := range lockfileNames {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// lockfileNames contains exact file names that identify lockfiles.
var lockfileNames = map[string]bool{
	"package-lock.json": true,
	// go.mod is the Go dependency source (selected versions). go.sum stays
	// classified so it is kept out of the content rule families, but the deps
	// analyzer no longer parses it — see deps.parseGoMod.
	"go.mod":             true,
	"go.sum":             true,
	"yarn.lock":          true,
	"poetry.lock":        true,
	"Gemfile.lock":       true,
	"Cargo.lock":         true,
	"pnpm-lock.yaml":     true,
	"requirements.txt":   true,
	"pom.xml":            true,
	"build.gradle":       true,
	"build.gradle.kts":   true,
	"packages.lock.json": true,
	"composer.lock":      true,
	"bom.json":           true,
	"sbom.json":          true,
}

// containerNames contains exact file names that identify container files.
var containerNames = map[string]bool{
	"Dockerfile":          true,
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
}

// sourceExtensions maps file extensions to the Source artifact type.
var sourceExtensions = map[string]bool{
	".go": true,
	".py": true,
	// JavaScript / TypeScript and their module + JSX variants. The React/Next
	// AI-app frontend keeps its LLM calls and prompt construction in .tsx/.jsx,
	// so omitting them left that code unclassified (and unscanned by
	// source-gated rules).
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
	".rb":    true,
	".java":  true,
	".kt":    true,
	".swift": true,
	".php":   true,
	".rs":    true,
	// C and C++ dialect extensions (translation units and headers). One taint
	// module (lexctx scan_cpp + engine extract_cpp + catalog `cpp` block) serves
	// every dialect since they share lexing and dangerous-API surface.
	".c": true, ".h": true,
	".cpp": true, ".cc": true, ".cxx": true, ".c++": true,
	".hpp": true, ".hh": true, ".hxx": true, ".ipp": true, ".inl": true,
	".cs": true,
	".sh": true,
	// Perl translation units, modules, CGI scripts, and test scripts. One taint
	// module (lexctx scan_perl + engine extract_perl + catalog `perl` block).
	".pl": true, ".pm": true, ".cgi": true, ".t": true,
	".scala": true,
	".sc":    true,
	// Objective-C / Objective-C++ translation units. Headers (.h/.hh/.hpp) are
	// already covered by the C/C++ set above and stay under that lexer; only the
	// implementation files carry the objc taint module (lexctx scan_objc + engine
	// extract_objc + the catalog `objc` block).
	".m":    true,
	".mm":   true,
	".ps1":  true,
	".psm1": true,
	".psd1": true,
	// Lua translation units. One taint module (lexctx scan_lua + engine
	// extract_lua + catalog `lua` block) serves scripts, OpenResty handlers, and
	// embedded config.
	".lua":  true,
	".dart": true,
	// Elixir source (.ex) and script (.exs) files. One taint module (lexctx
	// scan_elixir + engine extract_elixir + the catalog `elixir` block).
	".ex":  true,
	".exs": true,
	// Clojure source and ClojureScript / cross-platform variants. One taint
	// module (lexctx scan_clojure + engine extract_clojure + catalog `clojure`).
	".clj":  true,
	".cljs": true,
	".cljc": true,
	// Groovy source and Gradle build scripts (lexctx scan_groovy + engine
	// extract_groovy + catalog `groovy`). The extension-less Jenkinsfile is
	// classified by exact name via sourceNames below.
	".groovy": true,
	".gradle": true,
	// Extensions the lexer supports that were missing here, so files it can
	// fully analyse were not being classified as Source (and were skipped by
	// source-gated rules): Kotlin script, Ruby gemspec/rake, PHP templates,
	// Python stubs/interfaces, Clojure EDN, and .bash. A parity test against
	// lexctx.SourceExtensions now fails if this set falls behind the lexer again.
	".kts":     true,
	".gemspec": true,
	".rake":    true,
	".phtml":   true,
	".pyi":     true,
	".pyw":     true,
	".edn":     true,
	".bash":    true,
}

// sourceNames contains exact, extension-less file names that carry source code.
// A Jenkins pipeline lives in a `Jenkinsfile` (Groovy) with no extension, so an
// extension-only lookup misses it; Classify consults this by base name.
var sourceNames = map[string]bool{
	"Jenkinsfile": true,
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

	// Source by exact name (extension-less source files, e.g. Jenkinsfile).
	if sourceNames[name] {
		return Source
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
	if mcpConfigNames[name] {
		return true
	}
	if strings.HasSuffix(name, ".mcp.json") {
		return true
	}
	if strings.HasSuffix(name, ".prompt") {
		return true
	}
	if strings.HasSuffix(name, ".prompt.md") {
		return true
	}
	// The prompts/ and agents/ directory heuristic is a weak, path-only signal.
	// It must NOT claim files that are recognised source code: a .go/.ts/.py
	// living under a prompts/ or agents/ directory is exactly the LLM-prompt and
	// agent-driving code that most needs SAST, taint, and agentflow analysis —
	// all of which skip any artifact whose Type is not Source, so misclassifying
	// it as AIComponent silently drops it from those scans. The specific AI
	// signals above (mcp.json, *.prompt, and the agent-config names below) stay
	// authoritative; only this broad segment test yields to source. Such files
	// are still enriched by the AI analyzer when their content carries AI SDK
	// markers (see ai.ScanArtifacts's isSourceFile && isLikelyAIContent path).
	if !sourceExtensions[filepath.Ext(name)] && !sourceNames[name] &&
		(containsSegment(normalised, "prompts") || containsSegment(normalised, "agents")) {
		return true
	}
	if isAgentConfig(name, normalised) {
		return true
	}
	return false
}

// agentConfigNames are the fixed-name files that steer a coding agent — its
// rules, manifest, skills, and permission settings. They are an execution
// surface (a poisoned rule or an over-broad permission grant changes what the
// agent runs), so nox treats them as AI components and scans them (AGENT-*).
var agentConfigNames = map[string]bool{
	".cursorrules": true, ".clinerules": true, ".windsurfrules": true,
	"CLAUDE.md": true, "AGENTS.md": true, "GEMINI.md": true,
	"SKILL.md": true, "skill.md": true, "copilot-instructions.md": true,
}

// isAgentConfig reports whether a file is an agent-configuration artifact: a
// fixed-name rules/manifest/skill file, a Cursor `.mdc` rule, or a settings
// file living under a `.claude` or `.cursor` directory.
func isAgentConfig(name, normalised string) bool {
	if agentConfigNames[name] {
		return true
	}
	if strings.HasSuffix(name, ".mdc") {
		return true
	}
	if (name == "settings.json" || name == "settings.local.json") &&
		(containsSegment(normalised, ".claude") || containsSegment(normalised, ".cursor")) {
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

// dirContainsAnyIncluded reports whether any path in the include-set is
// at or under the given directory (relative, slash-separated). Used to
// short-circuit `filepath.Walk` descent when --changed-since restricts
// the scan to a small set of files. The root directory ("") is treated
// as containing every path so the walk always enters at least once.
func dirContainsAnyIncluded(relDir string, include map[string]bool) bool {
	if relDir == "" || relDir == "." {
		return len(include) > 0
	}
	prefix := relDir + "/"
	for p := range include {
		if p == relDir || strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// dirContainsAnyTracked reports whether any tracked path is at or under the
// given directory (relative, slash-separated). Used to keep the walker from
// pruning an ignored directory that still holds git-tracked files. The root
// ("" / ".") contains every tracked path.
func dirContainsAnyTracked(relDir string, tracked map[string]bool) bool {
	if len(tracked) == 0 {
		return false
	}
	if relDir == "" || relDir == "." {
		return true
	}
	prefix := relDir + "/"
	for p := range tracked {
		if p == relDir || strings.HasPrefix(p, prefix) {
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
	// IgnorePatterns holds gitignore-style patterns for skipping files at
	// the workspace root.
	IgnorePatterns []string
	// RespectGitignore controls whether nested .gitignore files and the
	// root patterns are applied during traversal. When false, every file
	// in the tree is walked regardless of ignore rules. Defaults to true.
	RespectGitignore bool
	// IncludePaths, when non-empty, restricts the walk to files whose
	// path (relative to Root, slash-separated) appears in the set. Used
	// by --changed-since to avoid walking unchanged subtrees. The walker
	// also short-circuits directory descent when no included path lives
	// under the current directory.
	IncludePaths map[string]bool
	// TrackedPaths holds the files git tracks (relative to Root, slash-
	// separated). git never ignores a tracked file, so a path in this set
	// is scanned even when a .gitignore pattern matches it — and an ignored
	// directory is still descended into when it contains a tracked file.
	// Empty (the default) means "no git context", so ignore rules apply as
	// before.
	TrackedPaths map[string]bool
	// ExcludePatterns are hard, explicit exclusions (from `scan.exclude` in
	// config): paths the user has said to never scan. Unlike gitignore
	// patterns, these are NOT overridden by TrackedPaths — a tracked file that
	// matches an exclude is still skipped, because the user asked for it
	// (e.g. a rule-definition file full of expected-false-positive patterns).
	ExcludePatterns []string
	// IncludePatterns, when non-empty, restricts the scan to files matching at
	// least one pattern (from `scan.include` in config). It is the glob-based
	// counterpart to IncludePaths, which holds exact paths for --changed-since;
	// when both are set a file must satisfy both.
	//
	// ExcludePatterns still wins: an operator who writes both means the
	// intersection, and exclude is the explicit "never scan this".
	//
	// Directories are still descended. A glob says nothing reliable about
	// whether a subtree can contain a match — "src/**/*.go" cannot tell you in
	// advance about src/a/b/ — and pruning on that guess silently loses files,
	// which is the failure this setting was reported for. Pruning a subtree out
	// of the walk is what ExcludePatterns is for.
	IncludePatterns []string
}

// MatchesInclude reports whether a file is allowed by an include pattern. It is
// exported so plugin findings are scoped by the same matcher the walk uses —
// "in scope" must mean one thing regardless of which analyzer found the issue.
func MatchesInclude(relSlash string, patterns []string) bool {
	return matchesInclude(relSlash, patterns)
}

// matchesInclude reports whether a file is allowed by an include pattern.
//
// The path itself is tested, and so is each of its ancestor directories. That
// is what makes "src" , "src/" and "src/**" all mean "everything under src",
// which is what an operator writing an allow-list means by any of them. Testing
// only the full path makes the three behave differently for no reason a reader
// could predict, and the difference shows up as quietly missing coverage.
func matchesInclude(relSlash string, patterns []string) bool {
	if IsIgnored(relSlash, patterns) {
		return true
	}
	for i := 0; i < len(relSlash); i++ {
		if relSlash[i] != '/' {
			continue
		}
		if IsIgnored(relSlash[:i], patterns) {
			return true
		}
	}
	return false
}

// NewWalker creates a Walker rooted at root with the DefaultClassifier
// registered. It attempts to load .gitignore patterns from the root directory;
// if no .gitignore exists the walker proceeds with no ignore patterns.
func NewWalker(root string) *Walker {
	reg := NewClassifierRegistry()
	reg.Register(&DefaultClassifier{})

	patterns, _ := LoadGitignore(root)

	return &Walker{
		Root:             root,
		Registry:         reg,
		IgnorePatterns:   patterns,
		RespectGitignore: true,
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

	// nestedPatterns maps an absolute directory path to its .gitignore
	// patterns. Nested gitignores apply to paths under their containing
	// directory.
	nestedPatterns := map[string][]string{}

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

		// Hard config excludes (scan.exclude) win unconditionally — they are
		// explicit "never scan this" rules, so the tracked-file override that
		// applies to .gitignore does NOT apply here. Checked before gitignore
		// and before IncludePaths so it holds even under --changed-since.
		if len(w.ExcludePatterns) > 0 && IsIgnored(filepath.ToSlash(rel), w.ExcludePatterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Config include allow-list (scan.include). Applied to files only, after
		// the hard excludes so exclude keeps winning.
		if len(w.IncludePatterns) > 0 && !info.IsDir() {
			if !matchesInclude(filepath.ToSlash(rel), w.IncludePatterns) {
				return nil
			}
		}

		if w.RespectGitignore {
			if info.IsDir() && path != absRoot {
				if pats, _ := LoadNestedGitignore(path); len(pats) > 0 {
					nestedPatterns[path] = pats
				}
			}

			if w.isIgnored(absRoot, path, rel, nestedPatterns) {
				relSlash := filepath.ToSlash(rel)
				if info.IsDir() {
					// Prune an ignored directory — unless it holds a tracked
					// file. git never ignores a tracked file, so we must
					// descend to reach one (e.g. a repo that .gitignores
					// `mobile/` but commits sources into it).
					if !dirContainsAnyTracked(relSlash, w.TrackedPaths) {
						return filepath.SkipDir
					}
				} else if !w.TrackedPaths[relSlash] {
					// Skip an ignored file unless it is tracked.
					return nil
				}
			}
		}

		// IncludePaths short-circuit: when an allow-list is supplied
		// (e.g. via --changed-since), skip dirs that don't contain any
		// included path and skip files not in the set. This avoids
		// walking unchanged subtrees in large monorepos.
		if len(w.IncludePaths) > 0 {
			relSlash := filepath.ToSlash(rel)
			if info.IsDir() {
				if !dirContainsAnyIncluded(relSlash, w.IncludePaths) {
					return filepath.SkipDir
				}
			} else if !w.IncludePaths[relSlash] {
				return nil
			}
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

// isIgnored reports whether a path should be skipped by the walker. It
// applies the root IgnorePatterns plus any nested .gitignore patterns from
// directories on the path between absRoot and the candidate.
func (w *Walker) isIgnored(absRoot, absPath, rel string, nested map[string][]string) bool {
	if IsIgnored(rel, w.IgnorePatterns) {
		return true
	}

	// Walk up the directory chain. For each ancestor that has a nested
	// gitignore, check the candidate path expressed relative to that
	// ancestor. This matches git's semantics: patterns in subdir/.gitignore
	// apply to paths inside subdir, not the workspace as a whole.
	dir := filepath.Dir(absPath)
	for dir != "" && strings.HasPrefix(dir, absRoot) {
		if pats, ok := nested[dir]; ok {
			scoped, err := filepath.Rel(dir, absPath)
			if err == nil && IsIgnored(scoped, pats) {
				return true
			}
		}
		if dir == absRoot {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}
