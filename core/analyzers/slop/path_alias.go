package slop

import (
	"encoding/json"
	"strings"
)

// A tsconfig/jsconfig `paths` entry maps an import specifier onto the project's
// own source tree. The specifier therefore names first-party code, which is
// what SLOP-001's proposition already excludes — but nothing in the specifier
// says so. `@shared/types` has exactly the shape npm requires of a scoped
// package, so it cannot be told from a real dependency without reading the
// project's config, and every one of them was reported as a hallucinated
// package a developer had installed.
//
// packageName narrows the EMPTY-scope case (`@/components`) on shape alone,
// since npm can hold no such name. This covers the rest, by reading what the
// project declares.
type aliasSet struct {
	// exact holds patterns with no `*`: the specifier must equal one.
	exact map[string]struct{}
	// prefixes holds the text before the `*` of each wildcard pattern. A
	// pattern's suffix is not checked: `*` matches to the end of the specifier
	// in every pattern TypeScript accepts here, and the prefix alone already
	// establishes that the project mapped this specifier onto its own tree.
	prefixes []string
}

// matches reports whether spec is covered by a declared path alias.
func (a *aliasSet) matches(spec string) bool {
	if a == nil {
		return false
	}
	if _, ok := a.exact[spec]; ok {
		return true
	}
	for _, p := range a.prefixes {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return false
}

// isPathAliasConfig reports whether base is a TypeScript/JavaScript project
// config that can carry `compilerOptions.paths`. Variants (tsconfig.app.json,
// tsconfig.node.json) are what a Vite or Nx workspace splits its config into,
// and any of them may hold the aliases.
func isPathAliasConfig(base string) bool {
	base = strings.ToLower(base)
	return (strings.HasPrefix(base, "tsconfig") || strings.HasPrefix(base, "jsconfig")) &&
		strings.HasSuffix(base, ".json")
}

// collectPathAliases reads `compilerOptions.paths` from every config supplied
// and unions the patterns.
//
// The union is repo-wide rather than per-directory: a monorepo declares an
// alias in the package that owns it, while the import being judged may sit in
// a sibling package that inherits the alias through `extends` or a workspace
// setting this analyzer does not resolve. Scoping the alias to its own
// directory would report those imports again. The cost is recall — a package
// whose name happens to match another package's alias prefix is not reported —
// and that trade is deliberate: a declared alias is evidence of first-party
// code, and SLOP-001 is a low-confidence heuristic whose false positives land
// on developers who did nothing wrong.
func collectPathAliases(configs map[string][]byte) *aliasSet {
	set := &aliasSet{exact: make(map[string]struct{})}
	for _, content := range configs {
		var cfg struct {
			CompilerOptions struct {
				Paths map[string]json.RawMessage `json:"paths"`
			} `json:"compilerOptions"`
		}
		if err := json.Unmarshal(stripJSONC(content), &cfg); err != nil {
			continue
		}
		for pattern := range cfg.CompilerOptions.Paths {
			star := strings.IndexByte(pattern, '*')
			switch {
			case star < 0:
				set.exact[pattern] = struct{}{}
			case star == 0:
				// `"*": [...]` maps every unresolved specifier onto the source
				// tree. Honouring it would silence the whole rule for this
				// project, so it is ignored: a catch-all says nothing about any
				// particular import.
				continue
			default:
				set.prefixes = append(set.prefixes, pattern[:star])
			}
		}
	}
	return set
}

// stripJSONC removes the comments and trailing commas that tsconfig files carry
// in practice — the TypeScript compiler accepts them, and the configs `tsc
// --init` and the framework templates generate ship with them, so a strict JSON
// parse fails on a large share of real projects.
//
// String literals are tracked so a `//` inside a path value survives, and the
// output keeps the input's byte positions where it can: characters are blanked
// rather than deleted, which keeps any future error offsets meaningful.
func stripJSONC(content []byte) []byte {
	out := make([]byte, len(content))
	copy(out, content)

	inString, escaped := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			for ; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return stripTrailingCommas(out)
}

// stripTrailingCommas blanks a comma that is followed only by whitespace and a
// closing brace or bracket.
func stripTrailingCommas(content []byte) []byte {
	inString, escaped := false, false
	for i := 0; i < len(content); i++ {
		c := content[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c != ',' {
			continue
		}
		for j := i + 1; j < len(content); j++ {
			switch content[j] {
			case ' ', '\t', '\r', '\n':
				continue
			case '}', ']':
				content[i] = ' '
			}
			break
		}
	}
	return content
}
