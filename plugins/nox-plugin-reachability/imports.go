package main

import (
	"bufio"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ImportSet tracks discovered imports grouped by ecosystem.
type ImportSet struct {
	byEcosystem map[string]map[string]bool // ecosystem -> set of import names
}

// NewImportSet creates an empty ImportSet.
func NewImportSet() *ImportSet {
	return &ImportSet{byEcosystem: make(map[string]map[string]bool)}
}

// Add records an import for a given ecosystem.
func (s *ImportSet) Add(ecosystem, name string) {
	if s.byEcosystem[ecosystem] == nil {
		s.byEcosystem[ecosystem] = make(map[string]bool)
	}
	s.byEcosystem[ecosystem][name] = true
}

// Contains reports whether name is imported in the given ecosystem.
func (s *ImportSet) Contains(ecosystem, name string) bool {
	m := s.byEcosystem[ecosystem]
	if m == nil {
		return false
	}
	return m[name]
}

// skippedDirs lists directories to skip during workspace walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
}

// ExtractImports walks root and extracts imports for Go, Python, and JS/TS files.
func ExtractImports(root string) (*ImportSet, error) {
	imports := NewImportSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".go":
			pkgs, parseErr := extractGoImports(path)
			if parseErr != nil {
				return nil // skip unparseable files
			}
			for _, pkg := range pkgs {
				imports.Add("Go", pkg)
			}
		case ".py":
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, pkg := range extractPyImports(content) {
				imports.Add("PyPI", pkg)
			}
		case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, pkg := range extractJSImports(content) {
				imports.Add("npm", pkg)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return imports, nil
}

// extractGoImports parses a Go source file and returns its import paths.
func extractGoImports(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}

	var imports []string
	for _, imp := range f.Imports {
		importPath := imp.Path.Value
		importPath = strings.Trim(importPath, `"`)
		if importPath != "" {
			imports = append(imports, importPath)
		}
	}
	return imports, nil
}

// Python import regexes.
var (
	rePyImport     = regexp.MustCompile(`^import\s+(\S+)`)
	rePyFromImport = regexp.MustCompile(`^from\s+(\S+)\s+import`)
)

// extractPyImports extracts top-level Python import names from source content.
func extractPyImports(content []byte) []string {
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := rePyFromImport.FindStringSubmatch(line); len(m) > 1 {
			pkg := topLevelModule(m[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
			}
		} else if m := rePyImport.FindStringSubmatch(line); len(m) > 1 {
			pkg := topLevelModule(m[1])
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
			}
		}
	}

	result := make([]string, 0, len(seen))
	for pkg := range seen {
		result = append(result, pkg)
	}
	return result
}

// topLevelModule extracts the top-level module from a dotted import path.
func topLevelModule(s string) string {
	if idx := strings.IndexByte(s, '.'); idx > 0 {
		return s[:idx]
	}
	return s
}

// JS/TS import regexes.
var (
	reJSImportFrom = regexp.MustCompile(`(?:import\s+.*?\s+from|import)\s*['"]([^'"]+)['"]`)
	reJSRequire    = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

// extractJSImports extracts package names from JS/TS import/require statements.
func extractJSImports(content []byte) []string {
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{reJSImportFrom, reJSRequire} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				pkg := normalizeJSPackage(m[1])
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
				}
			}
		}
	}

	result := make([]string, 0, len(seen))
	for pkg := range seen {
		result = append(result, pkg)
	}
	return result
}

// normalizeJSPackage extracts the npm package name from an import specifier.
// Skips relative imports (./foo, ../bar). Handles scoped packages (@scope/pkg).
func normalizeJSPackage(spec string) string {
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return "" // relative/absolute path, not a package
	}
	if strings.HasPrefix(spec, "@") {
		// Scoped package: @scope/pkg or @scope/pkg/sub
		parts := strings.SplitN(spec, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return spec
	}
	// Regular package: pkg or pkg/sub
	if idx := strings.IndexByte(spec, '/'); idx > 0 {
		return spec[:idx]
	}
	return spec
}

// pypiNameMap maps PyPI distribution names to their Python import names
// for common packages where the two differ.
var pypiNameMap = map[string]string{
	"pillow":          "PIL",
	"beautifulsoup4":  "bs4",
	"scikit-learn":    "sklearn",
	"pyyaml":          "yaml",
	"opencv-python":   "cv2",
	"python-dateutil": "dateutil",
	"python-dotenv":   "dotenv",
	"attrs":           "attr",
	"pyzmq":           "zmq",
	"pymongo":         "pymongo",
	"pyjwt":           "jwt",
	"python-magic":    "magic",
	"msgpack-python":  "msgpack",
	"pysocks":         "socks",
	"ruamel-yaml":     "ruamel",
}

// PyPIToImportName converts a PyPI distribution name to the corresponding
// Python import name. Returns the lowercase distribution name if no explicit
// mapping exists.
func PyPIToImportName(dist string) string {
	lower := strings.ToLower(dist)
	if mapped, ok := pypiNameMap[lower]; ok {
		return mapped
	}
	// Default: replace hyphens with underscores (PEP 503 normalization).
	return strings.ReplaceAll(lower, "-", "_")
}
