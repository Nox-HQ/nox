package source

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// ParseGoFile parses one Go source file, tolerating a partial AST.
//
// Every Go-AST analyzer re-implemented this: token.NewFileSet() then
// parser.ParseFile with SkipObjectResolution, keeping the partial AST a parse
// error leaves so a non-compiling snippet degrades to fewer findings rather than
// crashing the scan. They also disagreed on the filename handed to the parser —
// full path, basename, or a hardcoded "src.go" — so fset.Position().Filename
// reported different things per analyzer. This passes the real path
// consistently, and returns the fset the caller needs for line positions.
//
// SkipObjectResolution is deliberate: these analyzers do their own name
// tracking, and skipping identifier-object linking is faster and more
// error-tolerant. Comments are not parsed — a comment or string literal cannot
// be a call expression, so prose can never match a structural check.
//
// The returned *ast.File may be nil for input with no recoverable syntax;
// callers must nil-check it (walking a nil AST is a no-op but explicit is
// clearer).
func ParseGoFile(path string, content []byte) (*ast.File, *token.FileSet) {
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
	return file, fset
}

// ImportAliases returns the set of local names under which a file imports any of
// the given package paths — the package's default name, or an explicit alias.
//
// It resolves "which package does this call belong to", the check that keeps
// crypto/rand from being flagged as math/rand or crypto/tls from a random
// `tls`. Two analyzers had their own copy; drift here produces false
// positives/negatives directly. A blank (_) or dot (.) import is ignored: a
// blank import exposes no name to qualify a call, and a dot import is not a
// name this resolver can attribute.
func ImportAliases(file *ast.File, pkgPaths ...string) map[string]bool {
	want := make(map[string]bool, len(pkgPaths))
	for _, p := range pkgPaths {
		want[p] = true
	}
	out := map[string]bool{}
	if file == nil {
		return out
	}
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		if !want[path] {
			continue
		}
		if imp.Name != nil {
			if name := imp.Name.Name; name != "_" && name != "." {
				out[name] = true
			}
			continue
		}
		// No explicit alias: the local name is the path's last segment.
		out[lastPathSegment(path)] = true
	}
	return out
}

// lastPathSegment returns the default package name for an import path: its final
// "/"-separated segment, skipping a trailing major-version element (Go's
// convention keeps the package name across /v2, /v3, ... — math/rand/v2 is still
// package rand, not v2). This is not a general resolver — a package whose name
// differs from its path element still needs an explicit expected name — but it
// is correct for the standard-library and versioned-module cases these analyzers
// care about.
func lastPathSegment(path string) string {
	seg := path
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	if isMajorVersion(seg) {
		// Drop the /vN element and take the segment before it.
		rest := path[:len(path)-len(seg)-1]
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			return rest[i+1:]
		}
		return rest
	}
	return seg
}

// isMajorVersion reports whether seg is a Go major-version path element (v2, v3,
// ...). v0/v1 never appear as a path element, so they are not treated as one.
func isMajorVersion(seg string) bool {
	if len(seg) < 2 || seg[0] != 'v' {
		return false
	}
	for _, r := range seg[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return seg != "v0" && seg != "v1"
}
