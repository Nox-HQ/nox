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

// A tsconfig `paths` alias with a NON-EMPTY scope (`@shared/types`) has a valid
// package shape, so the empty-scope narrowing above cannot see it: telling it
// from a real dependency needs the project's own config read. Until it was,
// every such import was reported as a hallucinated package — the alias is
// first-party source by construction, which is precisely what SLOP-001
// excludes.
func TestTsconfigPathAliasIsNotAPhantomImport(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"package.json": `{"dependencies":{"react":"^18.0.0"}}`,
		"tsconfig.json": `{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@shared/*": ["./src/shared/*"],
      "@app": ["./src/app.ts"]
    }
  }
}`,
		"src/index.ts": `import type { LightItem } from "@shared/types";
import { boot } from "@app";
import React from "react";
import { thing } from "@ai-sdk/hallucinated-helper";
`,
	})
	for _, alias := range []string{"@shared/types", "@app"} {
		if hasPkg(pkgs, alias) {
			t.Errorf("false positive: %q is a tsconfig path alias, not a package; got %v", alias, pkgs)
		}
	}
	if !hasPkg(pkgs, "@ai-sdk/hallucinated-helper") {
		t.Errorf("recall lost: an undeclared scoped package must still be reported; got %v", pkgs)
	}
}

// jsconfig.json is the same file for a JavaScript project, and tsconfig files
// are JSONC in practice: the TypeScript compiler accepts comments and trailing
// commas, and the templates it generates ship with them.
func TestPathAliasesAreReadFromJsconfigAndJSONC(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"package.json": `{"dependencies":{}}`,
		"jsconfig.json": `{
  // Editor support for the alias below.
  "compilerOptions": {
    /* block comment */
    "paths": {
      "~/*": ["./src/*"],
      "@util/*": ["./src/util/*"],
    },
  },
}`,
		"src/index.js": `import a from "~/components/button";
import b from "@util/chat-store";
`,
	})
	if len(pkgs) != 0 {
		t.Errorf("false positives: %v — both specifiers are jsconfig path aliases", pkgs)
	}
}

// The unit half: pattern semantics. TypeScript allows at most one `*` in a
// pattern, and it matches a whole path segment sequence, not a substring.
func TestPathAliasMatching(t *testing.T) {
	aliases := collectPathAliases(map[string][]byte{
		"tsconfig.json": []byte(`{"compilerOptions":{"paths":{
			"@shared/*": ["./src/shared/*"],
			"@app": ["./src/app.ts"],
			"~/*": ["./src/*"]
		}}}`),
	})

	for _, spec := range []string{"@shared/types", "@shared/types/light", "@app", "~/lib/x"} {
		if !aliases.matches(spec) {
			t.Errorf("matches(%q) = false, want true — declared in tsconfig paths", spec)
		}
	}
	// Recall: a near-miss must stay a candidate. `@shared-utils` is a valid npm
	// package name and is NOT covered by the `@shared/*` pattern.
	for _, spec := range []string{"@shared-utils/x", "@sharedx/y", "@apple", "react", "@app/extra"} {
		if aliases.matches(spec) {
			t.Errorf("matches(%q) = true, want false — not covered by any alias", spec)
		}
	}
}

// No config, or a config with no paths, must leave behavior exactly as it was.
func TestNoPathAliasesLeavesEveryImportACandidate(t *testing.T) {
	aliases := collectPathAliases(nil)
	if aliases.matches("@shared/types") {
		t.Error("an empty alias set matched an import")
	}
	empty := collectPathAliases(map[string][]byte{
		"tsconfig.json": []byte(`{"compilerOptions":{"strict":true}}`),
	})
	if empty.matches("@shared/types") {
		t.Error("a tsconfig without paths matched an import")
	}
}
