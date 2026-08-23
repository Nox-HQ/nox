package slop

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// ecosystem identifies the package ecosystem an import belongs to.
type ecosystem string

const (
	ecoNPM  ecosystem = "npm"
	ecoPyPI ecosystem = "pypi"
)

// ecosystemForExt maps a source-file extension to the ecosystem whose imports
// it contains, or "" if the file is not one slop analyzes.
func ecosystemForExt(ext string) ecosystem {
	switch strings.ToLower(ext) {
	case ".py", ".pyi":
		return ecoPyPI
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return ecoNPM
	}
	return ""
}

// importRef is a single import specifier found in a source file, paired with
// the 1-based line it appears on.
type importRef struct {
	spec string
	line int
}

var (
	// Python: `import a.b as c, d` and `from a.b import c` / `from . import c`.
	pyImportRe = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+(.+)$`)
	pyFromRe   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.*[A-Za-z0-9_.]*)[ \t]+import\b`)

	// JS/TS: static import, dynamic import(), and require(). The specifier is the
	// single/double-quoted string in each construct.
	jsFromRe    = regexp.MustCompile(`(?m)\bfrom[ \t]+['"]([^'"\n]+)['"]`)
	jsBareRe    = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+['"]([^'"\n]+)['"]`)
	jsDynamicRe = regexp.MustCompile(`\bimport\s*\(\s*['"]([^'"\n]+)['"]`)
	jsRequireRe = regexp.MustCompile(`\brequire\s*\(\s*['"]([^'"\n]+)['"]`)
)

// extractImports returns every import specifier in content for the ecosystem,
// each tagged with its line number. Specifiers are returned verbatim (not yet
// resolved to package names); relative and builtin specifiers are filtered out
// downstream by packageName / stdlib membership.
func extractImports(eco ecosystem, content []byte) []importRef {
	switch eco {
	case ecoPyPI:
		return extractPythonImports(content)
	case ecoNPM:
		return extractJSImports(content)
	}
	return nil
}

// lineOf returns the 1-based line number of byte offset off within content.

func extractPythonImports(content []byte) []importRef {
	var refs []importRef
	// `import x.y as z, a.b` — split the tail on commas, take each module.
	for _, m := range pyImportRe.FindAllSubmatchIndex(content, -1) {
		line := lexctx.LineForOffset(content, m[0])
		tail := strings.TrimSpace(string(content[m[2]:m[3]]))
		// Strip trailing comments.
		if i := strings.IndexByte(tail, '#'); i >= 0 {
			tail = strings.TrimSpace(tail[:i])
		}
		for _, part := range strings.Split(tail, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// Drop an `as alias` suffix.
			if i := strings.Index(part, " as "); i >= 0 {
				part = strings.TrimSpace(part[:i])
			}
			// A bare "import" continued over parentheses can leave stray tokens;
			// only accept dotted identifiers.
			if !isPyModulePath(part) {
				continue
			}
			refs = append(refs, importRef{spec: part, line: line})
		}
	}
	// `from x import y` / `from . import y`.
	for _, m := range pyFromRe.FindAllSubmatchIndex(content, -1) {
		line := lexctx.LineForOffset(content, m[0])
		spec := string(content[m[2]:m[3]])
		refs = append(refs, importRef{spec: spec, line: line})
	}
	return refs
}

// isPyModulePath reports whether s looks like a dotted Python module path
// (identifiers separated by dots), so we ignore malformed capture tails.
func isPyModulePath(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			continue // leading dots (relative imports) are allowed
		}
		for i, r := range seg {
			if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				continue
			}
			if i > 0 && r >= '0' && r <= '9' {
				continue
			}
			return false
		}
	}
	return true
}

func extractJSImports(content []byte) []importRef {
	var refs []importRef
	add := func(res []int) {
		if res == nil {
			return
		}
		refs = append(refs, importRef{spec: string(content[res[2]:res[3]]), line: lexctx.LineForOffset(content, res[0])})
	}
	for _, re := range []*regexp.Regexp{jsFromRe, jsBareRe, jsDynamicRe, jsRequireRe} {
		for _, m := range re.FindAllSubmatchIndex(content, -1) {
			add(m)
		}
	}
	return refs
}

// packageName resolves a raw import specifier to the top-level distribution
// package name for its ecosystem. ok is false when the specifier is a
// relative/local import that references no external package.
func packageName(eco ecosystem, spec string) (name string, ok bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	switch eco {
	case ecoPyPI:
		if strings.HasPrefix(spec, ".") { // relative import
			return "", false
		}
		root := spec
		if i := strings.IndexByte(root, '.'); i >= 0 {
			root = root[:i]
		}
		if root == "" {
			return "", false
		}
		return root, true
	case ecoNPM:
		if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
			return "", false
		}
		spec = strings.TrimPrefix(spec, "node:")
		if strings.HasPrefix(spec, "@") { // scoped: @scope/name[/subpath]
			parts := strings.SplitN(spec, "/", 3)
			if len(parts) < 2 {
				return spec, true
			}
			return parts[0] + "/" + parts[1], true
		}
		if i := strings.IndexByte(spec, '/'); i >= 0 {
			spec = spec[:i]
		}
		if spec == "" {
			return "", false
		}
		return spec, true
	}
	return "", false
}
