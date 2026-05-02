// Polyglot import extractors. Each function consumes a source file's
// content and returns the set of external package / crate / gem / nuget
// references discovered. Extractors are intentionally regex-based so the
// plugin stays lightweight; precision is "best-effort, over-report" —
// false positives are fine because they only inflate the apparent
// reachability set, never reduce it. The downstream Analyze() step
// preserves "unknown" status so operators don't act on noise.

package main

import (
	"bufio"
	"regexp"
	"strings"
)

// Rust ----------------------------------------------------------------
var (
	// `use foo::bar;` — top-level external crate name is the first segment.
	reRustUse = regexp.MustCompile(`^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:::|;)`)
	// `extern crate foo;` (older Rust 2015 edition style).
	reRustExternCrate = regexp.MustCompile(`^\s*extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

// rustBuiltins lists Rust's std library top-level modules. Imports of
// these are NOT external crates and must be excluded from reachability.
var rustBuiltins = map[string]bool{
	"std": true, "core": true, "alloc": true, "self": true, "super": true,
	"crate": true, "Self": true,
}

func extractRustUses(content []byte) []string {
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{reRustUse, reRustExternCrate} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				name := m[1]
				if rustBuiltins[name] {
					continue
				}
				seen[name] = true
			}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// Java / Kotlin -------------------------------------------------------
var reJavaImport = regexp.MustCompile(`^\s*import\s+(?:static\s+)?([a-zA-Z_][\w.]*)\s*(?:\.\*)?\s*;?`)

// javaBuiltinPrefixes lists JDK / Kotlin stdlib top-level packages that
// must be excluded — they aren't external Maven dependencies.
var javaBuiltinPrefixes = []string{
	"java.", "javax.", "jdk.", "sun.", "com.sun.",
	"kotlin.", "kotlinx.",
}

func extractJavaImports(content []byte) []string {
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		m := reJavaImport.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		fq := m[1]
		if isJavaBuiltin(fq) {
			continue
		}
		// Maven coordinates use group:artifact. We can only see the
		// fully-qualified import path; map to the top three segments
		// which usually correspond to group + leading artifact prefix.
		// e.g. "org.apache.commons.lang3.StringUtils" → "org.apache.commons".
		seen[topThreeSegments(fq)] = true
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func isJavaBuiltin(fq string) bool {
	for _, prefix := range javaBuiltinPrefixes {
		if strings.HasPrefix(fq, prefix) {
			return true
		}
	}
	return false
}

func topThreeSegments(fq string) string {
	parts := strings.SplitN(fq, ".", 4)
	if len(parts) < 3 {
		return fq
	}
	return parts[0] + "." + parts[1] + "." + parts[2]
}

// Ruby ----------------------------------------------------------------
var (
	reRubyRequire  = regexp.MustCompile(`^\s*require\s*\(?\s*['"]([^'"]+)['"]`)
	reRubyAutoload = regexp.MustCompile(`autoload\s+:\w+\s*,\s*['"]([^'"]+)['"]`)
)

func extractRubyRequires(content []byte) []string {
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// require_relative loads project-local files, never external
		// gems. Skip those lines outright.
		if strings.Contains(line, "require_relative") {
			continue
		}
		for _, re := range []*regexp.Regexp{reRubyRequire, reRubyAutoload} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				spec := m[1]
				if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
					continue
				}
				// Top-level segment is the gem name (e.g.
				// "active_record/connection_adapters" → "active_record").
				if idx := strings.IndexByte(spec, '/'); idx > 0 {
					spec = spec[:idx]
				}
				seen[spec] = true
			}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// C# / .NET -----------------------------------------------------------
var reCSharpUsing = regexp.MustCompile(`^\s*(?:global\s+)?using\s+(?:static\s+)?(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_][\w.]*)\s*;`)

// dotnetBuiltinPrefixes lists BCL namespaces that aren't NuGet
// dependencies.
var dotnetBuiltinPrefixes = []string{
	"System", "Microsoft.Win32", "Microsoft.CSharp", "Microsoft.VisualBasic",
}

func extractCSharpUsings(content []byte) []string {
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		m := reCSharpUsing.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		ns := m[1]
		if isDotNetBuiltin(ns) {
			continue
		}
		// Map full namespace to top-two segments (NuGet packages
		// usually publish under a stable two-segment root).
		seen[topTwoSegments(ns)] = true
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func isDotNetBuiltin(ns string) bool {
	for _, prefix := range dotnetBuiltinPrefixes {
		if ns == prefix || strings.HasPrefix(ns, prefix+".") {
			return true
		}
	}
	return false
}

func topTwoSegments(ns string) string {
	parts := strings.SplitN(ns, ".", 3)
	if len(parts) < 2 {
		return ns
	}
	return parts[0] + "." + parts[1]
}
