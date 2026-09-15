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
func extractImports(eco ecosystem, lang lexctx.Lang, content []byte) []importRef {
	// An import statement quoted inside a string or a comment is not an import.
	//
	// vercel/ai's content/tools-registry/registry.ts carries documentation code
	// samples in template literals:
	//
	//	codeExample: `import { generateText } from 'ai';
	//	import { executeCode } from 'ai-sdk-tool-code-execution';`
	//
	// Those are text to be displayed, not modules to be resolved, and the
	// specifier inside them is a perfectly ordinary npm name -- so no check on
	// the NAME can tell them apart from a real import. What tells them apart is
	// where the `import` keyword sits: in a real import it is code, and in these
	// it is inside a backtick string. 17 findings in that one file, each
	// asserting the project depended on a package it was only documenting.
	//
	// lexctx already classifies JS template literals and Python docstrings, so
	// this costs one pass and no new lexer. For LangUnknown it returns a single
	// code region spanning the file, which degrades to exactly the old
	// behaviour rather than to silence.
	regions := lexctx.Classify(lang, content)
	inCode := func(off int) bool { return lexctx.KindAt(regions, off) == lexctx.KindCode }

	switch eco {
	case ecoPyPI:
		return extractPythonImports(content, inCode)
	case ecoNPM:
		return extractJSImports(content, inCode)
	}
	return nil
}

// lineOf returns the 1-based line number of byte offset off within content.

func extractPythonImports(content []byte, inCode func(int) bool) []importRef {
	var refs []importRef
	// `import x.y as z, a.b` — split the tail on commas, take each module.
	for _, m := range pyImportRe.FindAllSubmatchIndex(content, -1) {
		if !inCode(m[0]) {
			continue // an import inside a docstring or a comment
		}
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
		if !inCode(m[0]) {
			continue
		}
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

func extractJSImports(content []byte, inCode func(int) bool) []importRef {
	var refs []importRef
	add := func(res []int) {
		if res == nil {
			return
		}
		// res[0] is the `import`/`from`/`require` keyword, which is code in a
		// real import and string in a quoted code sample. The specifier itself
		// is a string either way, so it cannot be what is tested.
		if !inCode(res[0]) {
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
		// `#name` is a Node.js subpath import: resolved through the importing
		// package's own "imports" field, so it is package-internal by
		// specification and can never name a registry package.
		if strings.HasPrefix(spec, "#") {
			return "", false
		}
		if strings.HasPrefix(spec, "@") { // scoped: @scope/name[/subpath]
			parts := strings.SplitN(spec, "/", 3)
			if len(parts) < 2 {
				return spec, true
			}
			// An EMPTY scope is not a package name. npm requires
			// `@scope/name` with a non-empty scope, so `@/components` cannot
			// resolve to anything in any registry -- it is the near-universal
			// tsconfig `paths` alias for the project's own source root, and
			// SLOP-001's own proposition already excludes a first-party module.
			//
			// This was 793 of the family's 1,293 findings on the pinned corpus
			// -- 61.3% -- led by `@/components` (251), `@/agent` (199) and
			// `@/lib` (152). Reporting them said a developer had installed a
			// hallucinated package, when what they had done was configure a
			// path alias.
			//
			// Resolving tsconfig `paths` properly would additionally cover
			// aliases with a non-empty scope (`@util/chat-store`), which this
			// does not: those are a valid package shape and need the config
			// read to tell them from a real dependency.
			if parts[0] == "@" {
				return "", false
			}
			name := parts[0] + "/" + parts[1]
			if !isNPMPackageName(name) {
				return "", false
			}
			return name, true
		}
		if i := strings.IndexByte(spec, '/'); i >= 0 {
			spec = spec[:i]
		}
		if spec == "" || !isNPMPackageName(spec) {
			return "", false
		}
		return spec, true
	}
	return "", false
}

// npmNameSegment is the character set an npm package name segment can hold. The
// registry accepts URL-safe characters only, so a specifier carrying anything
// else is not a name any registry could serve.
var npmNameSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*$`)

// isNPMPackageName reports whether name could be a package on a registry.
//
// SLOP-001 says "this import resolves to no declared dependency", and reads
// that as evidence of a hallucinated package. That inference needs the
// specifier to be a package name in the first place. It is not, when the import
// statement is being GENERATED rather than executed:
//
//	await import('${moduleName}');                                   // load-time.ts
//	import transformer from '${toRelativeImportPath(paths.test, …)}'; // scaffold-codemod.ts
//
// Those lines sit inside a template literal that writes a source file. The
// extractor's regexes match single and double quotes, which is correct for real
// imports and also matches the quoted specifier inside the generated text, so
// `${moduleName}` was reported as a dependency the project had failed to
// declare. No registry can serve a name containing `$`, `{` or `}`, so the
// check is exact rather than heuristic: it excludes what cannot exist, not what
// looks unusual.
//
// Scoped names are checked per segment by the caller, which has already split
// `@scope/name` — so this sees `@scope/name` whole and validates both halves.
func isNPMPackageName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	if strings.HasPrefix(name, "@") {
		scope, rest, ok := strings.Cut(name[1:], "/")
		return ok && npmNameSegment.MatchString(scope) && npmNameSegment.MatchString(rest)
	}
	return npmNameSegment.MatchString(name)
}
