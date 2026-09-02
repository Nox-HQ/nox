// Package depimports answers one question for a dependency finding, in every
// language nox can answer it soundly: does this project's own source import the
// package the advisory names?
//
// It exists because dependency applicability was implemented for Go alone.
// nox is a language-agnostic scanner, so "is this dependency used?" answered
// only for Go is a Go feature wearing a general name — and it left every npm,
// PyPI, Cargo, pub and RubyGems finding reported as unexamined.
//
// # Only ever climbing
//
// A positive answer here establishes the SymbolUsed rung. A negative answer
// establishes NOTHING and must never refute one.
//
// The reason is that a distribution's name and its import name are different
// strings in most ecosystems — PyPI ships PyYAML as `yaml` and beautifulsoup4
// as `bs4` — and a package this project never imports directly may still be
// used by a package it does import. Reading either miss as "not impacting"
// would turn an unknown into an all-clear, which is the one error a
// vulnerability scanner must not make. Every failure mode here therefore
// degrades to exactly today's behaviour: no climb.
//
// # Which ecosystems, and why not the rest
//
// Covered: npm, PyPI, Cargo, pub and RubyGems — the ecosystems whose import
// statement names the distribution, so a match means what it appears to mean.
//
// Not covered: Maven, NuGet, Packagist and Hex, whose imports name a namespace
// (`com.fasterxml.jackson.databind`, `System.Text.Json`) that the manifest does
// not carry. Resolving those needs the package's own metadata, not its name.
// Guessing would produce matches nobody has checked, in the direction that
// silently promotes a finding's priority.
package depimports

import (
	"path"
	"regexp"
	"strings"
)

// Index records which module identifiers a source tree imports, per ecosystem,
// and — separately — whether any source for that ecosystem was seen at all.
//
// The two are not the same fact. "No Python file imports requests" and "there
// is no Python here" both produce an empty set, and only the first is evidence.
type Index struct {
	imports map[string]map[string]struct{}
	seen    map[string]bool
}

// New returns an empty Index. A zero tree answers Known(false) for everything,
// which is the honest answer when nothing was read.
func New() *Index {
	return &Index{imports: map[string]map[string]struct{}{}, seen: map[string]bool{}}
}

// ecosystemFor maps a file extension to the dependency ecosystem its imports
// name. Extensions absent here contribute nothing.
var ecosystemFor = map[string]string{
	".js": "npm", ".jsx": "npm", ".mjs": "npm", ".cjs": "npm",
	".ts": "npm", ".tsx": "npm",
	".py":   "pypi",
	".rs":   "cargo",
	".dart": "pub",
	".rb":   "rubygems",
}

// Add reads one file's imports into the index. Unknown extensions are ignored.
func (ix *Index) Add(filePath string, content []byte) {
	eco, ok := ecosystemFor[strings.ToLower(path.Ext(filePath))]
	if !ok {
		return
	}
	// Seeing the file is what makes a later absence meaningful, so record it
	// before extraction and regardless of whether anything was found.
	ix.seen[eco] = true
	set := ix.imports[eco]
	if set == nil {
		set = map[string]struct{}{}
		ix.imports[eco] = set
	}
	for _, m := range extract(eco, string(content)) {
		if m != "" {
			set[m] = struct{}{}
		}
	}
}

// Known reports whether any source file of this ecosystem's languages was read.
func (ix *Index) Known(ecosystem string) bool { return ix.seen[normalizeEco(ecosystem)] }

// Imports reports whether the source imports the given distribution.
//
// Matching is on the normalised name, which is what makes `serde-json` in a
// Cargo manifest match `use serde_json` in source. A false answer means only
// that no import matched — never that the package is unused.
func (ix *Index) Imports(ecosystem, pkg string) bool {
	eco := normalizeEco(ecosystem)
	set := ix.imports[eco]
	if set == nil {
		return false
	}
	_, ok := set[normalizeName(eco, pkg)]
	return ok
}

// Supported reports whether this ecosystem's import statements name the
// distribution closely enough for a match to mean anything.
func Supported(ecosystem string) bool {
	switch normalizeEco(ecosystem) {
	case "npm", "pypi", "cargo", "pub", "rubygems":
		return true
	}
	return false
}

// normalizeEco folds the spellings OSV, lockfiles and nox's own analyzers use
// for the same ecosystem onto one key.
func normalizeEco(e string) string {
	switch strings.ToLower(strings.TrimSpace(e)) {
	case "npm":
		return "npm"
	case "pypi", "pip", "python":
		return "pypi"
	case "cargo", "crates.io", "crates":
		return "cargo"
	case "pub", "dart":
		return "pub"
	case "rubygems", "gem", "ruby":
		return "rubygems"
	}
	return strings.ToLower(strings.TrimSpace(e))
}

// normalizeName folds a distribution name and an import identifier onto one
// spelling. Cargo and PyPI both treat `-` and `_` as the same character in this
// position; npm scopes are case-sensitive only in theory and lowercase in
// practice.
func normalizeName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch eco {
	case "cargo", "pypi":
		n = strings.ReplaceAll(n, "-", "_")
	}
	return n
}

var (
	// require("x") / require('x')
	jsRequireRE = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	// import ... from "x" / import "x" / export ... from "x"
	jsFromRE = regexp.MustCompile(`(?m)(?:^|\s)(?:import|export)\b[^;'"]*?from\s*['"]([^'"]+)['"]`)
	jsBareRE = regexp.MustCompile(`(?m)^\s*import\s*['"]([^'"]+)['"]`)
	// import x / import x.y as z
	pyImportRE = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_][\w.]*)`)
	pyFromRE   = regexp.MustCompile(`(?m)^\s*from\s+([A-Za-z_][\w.]*)\s+import\b`)
	// use crate::x is internal; use foo::bar names crate foo
	rsUseRE    = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?use\s+([A-Za-z_]\w*)\s*(?:::|;)`)
	rsExternRE = regexp.MustCompile(`(?m)^\s*extern\s+crate\s+([A-Za-z_]\w*)`)
	// import 'package:foo/bar.dart'
	dartRE = regexp.MustCompile(`(?m)^\s*(?:import|export)\s+['"]package:([^/'"]+)`)
	// require 'foo' / require "foo/bar"
	rbRequireRE = regexp.MustCompile(`(?m)^\s*require(?:_relative)?\s*\(?\s*['"]([^'"]+)['"]`)
)

// extract returns the distribution names an ecosystem's source imports.
func extract(eco, src string) []string {
	var out []string
	add := func(ms [][]string, f func(string) string) {
		for _, m := range ms {
			if len(m) > 1 {
				out = append(out, normalizeName(eco, f(m[1])))
			}
		}
	}
	switch eco {
	case "npm":
		add(jsRequireRE.FindAllStringSubmatch(src, -1), npmPackage)
		add(jsFromRE.FindAllStringSubmatch(src, -1), npmPackage)
		add(jsBareRE.FindAllStringSubmatch(src, -1), npmPackage)
	case "pypi":
		add(pyImportRE.FindAllStringSubmatch(src, -1), topSegment)
		add(pyFromRE.FindAllStringSubmatch(src, -1), topSegment)
	case "cargo":
		add(rsUseRE.FindAllStringSubmatch(src, -1), rustCrate)
		add(rsExternRE.FindAllStringSubmatch(src, -1), rustCrate)
	case "pub":
		add(dartRE.FindAllStringSubmatch(src, -1), func(s string) string { return s })
	case "rubygems":
		add(rbRequireRE.FindAllStringSubmatch(src, -1), topSegment)
	}
	return out
}

// npmPackage reduces a module specifier to the installed package: `lodash/fp`
// is lodash, `@babel/core/lib` is @babel/core. A relative or absolute path is
// this project's own file and names no package.
func npmPackage(spec string) string {
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	// `node:fs` explicitly names the builtin. Mapping it to the npm package
	// `fs` — which exists — would climb a rung on a module that was never
	// installed, and climbing wrongly is the only direction that misleads.
	if strings.HasPrefix(spec, "node:") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// topSegment takes the first dotted or slashed segment: `os.path` is os,
// `active_support/core_ext` is active_support.
func topSegment(s string) string {
	if i := strings.IndexAny(s, "./"); i > 0 {
		return s[:i]
	}
	return s
}

// rustCrate drops the paths that name this crate rather than a dependency.
func rustCrate(name string) string {
	switch name {
	case "crate", "self", "super", "std", "core", "alloc":
		return ""
	}
	return name
}
