// Package slop detects slopsquatting / package-hallucination risk: source-code
// imports that reference an external package which is not declared in any of the
// project's dependency manifests, is not part of the language standard library,
// and is not a first-party/local module.
//
// Such "phantom" imports are the attack surface for slopsquatting — an LLM
// hallucinates a plausible-sounding package name in generated code, a developer
// installs it, and an attacker who pre-registered that name executes code on the
// developer's machine. The check is fully deterministic and offline: it compares
// import roots against embedded standard-library lists and the packages the
// project actually declares. It never contacts a registry.
package slop

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer performs phantom-import detection.
type Analyzer struct{}

// NewAnalyzer returns a slop analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rule set for the slopsquatting analyzer.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          "SLOP-001",
		Version:     "1.0",
		Description: "Imported package is not declared in any dependency manifest (possible hallucinated / slopsquatted package)",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceLow,
		Tags:        []string{"dependency", "supply-chain", "slopsquatting", "ai", "owasp-asi04", "owasp-llm03"},
		Remediation: "This source file imports a package that is not declared in any dependency manifest, is not a standard-library module, and is not a local module. AI code generators frequently hallucinate plausible-but-nonexistent package names; attackers pre-register those names (\"slopsquatting\"). Before installing it, verify the package exists on its registry and is the one you intend. If it is a real dependency, declare it in your manifest; if it is a local module, adjust your import path.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1357.html",
			"https://genai.owasp.org/llmrisk/llm03-supply-chain/",
		},
		Metadata: map[string]string{"cwe": "CWE-1357"},
	})
	return rs
}

// manifestBasenames are the dependency manifests slop reads to learn which
// packages a project declares. Matched case-insensitively against the basename.
func isManifest(base string) bool {
	base = strings.ToLower(base)
	switch base {
	case "package.json", "package-lock.json", "pyproject.toml", "pipfile":
		return true
	}
	return base == "requirements.txt" ||
		(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"))
}

// ScanArtifacts detects phantom imports across the discovered source files.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	// Gather declared packages from manifests and first-party module roots from
	// the source tree before evaluating any import.
	manifests := make(map[string][]byte)
	local := make(map[string]struct{})
	for i := range artifacts {
		art := artifacts[i]
		base := filepath.Base(art.Path)
		if isManifest(base) {
			if content, err := os.ReadFile(art.AbsPath); err == nil {
				manifests[art.Path] = content
			}
		}
		if art.Type == discovery.Source {
			for root := range localModuleRoots(art.Path) {
				local[root] = struct{}{}
			}
		}
	}
	declared := collectDeclared(manifests)

	for i := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := artifacts[i]
		if art.Type != discovery.Source {
			continue
		}
		eco := ecosystemForExt(filepath.Ext(art.Path))
		if eco == "" {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		a.scanFile(fs, eco, art.Path, content, declared, local)
	}
	return fs, nil
}

// scanFile evaluates one source file's imports and adds a SLOP-001 finding for
// each undeclared external package (deduplicated per package within the file).
func (a *Analyzer) scanFile(fs *findings.FindingSet, eco ecosystem, path string, content []byte, declared *declaredSet, local map[string]struct{}) {
	seen := make(map[string]struct{})
	for _, imp := range extractImports(eco, content) {
		pkg, ok := packageName(eco, imp.spec)
		if !ok {
			continue // relative/local specifier
		}
		if isStdlib(eco, pkg) {
			continue
		}
		if _, isLocal := local[pkg]; isLocal && eco == ecoPyPI {
			continue // first-party Python module
		}
		if declaredHas(declared, eco, pkg) {
			continue
		}
		if _, dup := seen[pkg]; dup {
			continue
		}
		seen[pkg] = struct{}{}
		fs.Add(findings.Finding{
			RuleID:     "SLOP-001",
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceLow,
			Location:   findings.Location{FilePath: path, StartLine: imp.line, EndLine: imp.line},
			Message:    "Imported package \"" + pkg + "\" is not declared in any dependency manifest, standard library, or local module — verify it exists before installing (slopsquatting risk).",
			Metadata: map[string]string{
				"package":   pkg,
				"ecosystem": string(eco),
				"import":    imp.spec,
			},
		})
	}
}

func declaredHas(d *declaredSet, eco ecosystem, pkg string) bool {
	switch eco {
	case ecoNPM:
		return d.hasNPM(pkg)
	case ecoPyPI:
		return d.hasPyPI(pkg)
	}
	return false
}

// localModuleRoots returns the candidate first-party module roots implied by a
// source file's path: the top-level directory segment, a src/-stripped segment,
// and the stem of a top-level file. Python imports whose root matches one of
// these are treated as first-party rather than external.
func localModuleRoots(path string) map[string]struct{} {
	roots := make(map[string]struct{})
	path = filepath.ToSlash(path)
	segs := strings.Split(path, "/")
	if len(segs) == 0 {
		return roots
	}
	first := segs[0]
	if len(segs) == 1 { // top-level file: foo.py → module "foo"
		roots[strings.TrimSuffix(first, filepath.Ext(first))] = struct{}{}
		return roots
	}
	// A directory at the tree root is an importable package root.
	roots[first] = struct{}{}
	// Common "src layout": src/<pkg>/... → <pkg> is the package root.
	if (first == "src" || first == "lib") && len(segs) >= 3 {
		roots[segs[1]] = struct{}{}
	}
	return roots
}
