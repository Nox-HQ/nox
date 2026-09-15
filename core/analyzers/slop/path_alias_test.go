package slop

import "testing"

// SLOP-001 reports an import that resolves to no manifest entry, no standard
// library and no first-party module: the slopsquatting attack surface, where a
// developer installs a package an LLM hallucinated.
//
// `@/components` is none of those things. It is the near-universal tsconfig
// `paths` alias for a project's own source root, and it is not a package name
// at all: npm requires `@scope/name` with a NON-EMPTY scope, so a specifier
// with an empty scope cannot resolve to anything in any registry.
//
// Measured on the pinned corpus, this was 793 of the family's 1,293 findings --
// 61.3% -- led by `@/components` (251), `@/agent` (199) and `@/lib` (152). Each
// one told a developer they had installed a hallucinated package when what they
// had done was configure a path alias.

func TestAnEmptyScopeIsNotAPackage(t *testing.T) {
	for _, spec := range []string{
		"@/components",
		"@/agent",
		"@/lib/utils",
		"@/",
	} {
		if name, ok := packageName(ecoNPM, spec); ok {
			t.Errorf("packageName(npm, %q) = %q, true — an empty npm scope is not a "+
				"package name, so this cannot be a slopsquat candidate", spec, name)
		}
	}
}

// TestNodeSubpathImportsAreInternal. `#name` resolves through the importing
// package's own "imports" field, so it is package-internal by specification.
func TestNodeSubpathImportsAreInternal(t *testing.T) {
	for _, spec := range []string{"#internal/db", "#config"} {
		if name, ok := packageName(ecoNPM, spec); ok {
			t.Errorf("packageName(npm, %q) = %q, true — a Node subpath import never "+
				"names a registry package", spec, name)
		}
	}
}

// TestRealScopedPackagesStillResolve is the recall half. Narrowing must not
// swallow a genuinely scoped dependency, which is where real slopsquat targets
// live.
func TestRealScopedPackagesStillResolve(t *testing.T) {
	for spec, want := range map[string]string{
		"@ai-sdk/openai":         "@ai-sdk/openai",
		"@ai-sdk/provider/utils": "@ai-sdk/provider",
		"@perplexity-ai/ai-sdk":  "@perplexity-ai/ai-sdk",
		"@util/chat-store":       "@util/chat-store",
		"react":                  "react",
		"node:fs":                "fs",
		"lodash/fp":              "lodash",
	} {
		got, ok := packageName(ecoNPM, spec)
		if !ok || got != want {
			t.Errorf("packageName(npm, %q) = %q,%v — want %q,true", spec, got, ok, want)
		}
	}
}

// TestRelativeImportsStayLocal guards the case that already worked.
func TestRelativeImportsStayLocal(t *testing.T) {
	for _, spec := range []string{"./local", "../sibling", "/abs/path"} {
		if _, ok := packageName(ecoNPM, spec); ok {
			t.Errorf("packageName(npm, %q) resolved to a package", spec)
		}
	}
}
