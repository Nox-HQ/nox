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

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer performs phantom-import detection and, when a predictive feed is
// loaded, high-risk slopsquat-target detection (SLOP-002).
type Analyzer struct {
	// feed is an optional, verified predictive slopsquat blocklist. When nil
	// (the default), the analyzer's behavior is exactly the reactive SLOP-001
	// check and nothing else — no feed means zero behavior change. When set, an
	// imported name that matches a feed entry additionally raises a distinct
	// SLOP-002 predictive finding; the SLOP-001 baseline is never altered.
	feed *feed.Loaded
}

// Option configures an Analyzer.
type Option func(*Analyzer)

// WithFeed attaches a verified predictive slopsquat blocklist. Passing a nil
// feed is a no-op, so callers can wire it unconditionally.
func WithFeed(f *feed.Loaded) Option {
	return func(a *Analyzer) {
		if f != nil {
			a.feed = f
		}
	}
}

// NewAnalyzer returns a slop analyzer. With no options it is the reactive
// SLOP-001 analyzer; WithFeed adds the predictive SLOP-002 dimension.
func NewAnalyzer(opts ...Option) *Analyzer {
	a := &Analyzer{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

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
	rs.Add(&rules.Rule{
		ID:          "SLOP-002",
		Version:     "1.0",
		Description: "Imported package matches a known high-risk slopsquat target from the predictive blocklist feed",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"dependency", "supply-chain", "slopsquatting", "ai", "predictive", "owasp-asi04", "owasp-llm03"},
		Remediation: "This source file imports a package name that appears on a predictive slopsquat blocklist: a name an LLM is likely to hallucinate that was verified UNREGISTERED (squattable) when the feed was generated. Either the name is a phantom import (a hallucinated dependency you should remove) or — if the package is now installed — it may be a squat an attacker registered after the feed date. Do not install or run it until you confirm, on the official registry, that the package exists, is the one you intend, and is published by a trusted maintainer. Prefer the real upstream package the name imitates.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1357.html",
			"https://genai.owasp.org/llmrisk/llm03-supply-chain/",
		},
		Metadata: map[string]string{"cwe": "CWE-1357"},
	})
	return rs
}

// predictiveSeverity maps a feed risk tier to a SLOP-002 finding severity. The
// mapping is deliberately one notch below the tier's face value: SLOP-002 is a
// predictive heuristic ("this name is a known squat target"), not proof of
// compromise, so a critical-tier target is reported High, not Critical.
func predictiveSeverity(tier string) findings.Severity {
	switch tier {
	case feed.TierCritical:
		return findings.SeverityHigh
	case feed.TierHigh:
		return findings.SeverityMedium
	default: // medium and anything unexpected
		return findings.SeverityLow
	}
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
	seenPred := make(map[string]struct{})
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

		// Predictive dimension (additive, opt-in): when a feed is loaded and the
		// imported name matches a high-risk squattable target, raise a distinct
		// SLOP-002 finding. This runs BEFORE the declared-manifest check because
		// a name that is already declared/installed and on the blocklist is the
		// dangerous "you may have installed the squat" case that SLOP-001, which
		// only fires on unresolved imports, cannot catch. With no feed loaded
		// this block is skipped entirely — zero behavior change.
		a.emitPredictive(fs, eco, path, pkg, imp, seenPred)

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

// emitPredictive raises a SLOP-002 finding when a loaded feed classifies pkg as
// a high-risk slopsquat target. It is a no-op when no feed is loaded, so the
// analyzer's baseline (SLOP-001) output is identical with or without a feed.
// Findings are deduplicated per package within a file.
func (a *Analyzer) emitPredictive(fs *findings.FindingSet, eco ecosystem, path, pkg string, imp importRef, seen map[string]struct{}) {
	if a.feed == nil {
		return
	}
	entry, ok := a.feed.Lookup(string(eco), pkg)
	if !ok {
		return
	}
	if _, dup := seen[pkg]; dup {
		return
	}
	seen[pkg] = struct{}{}
	fs.Add(findings.Finding{
		RuleID:     "SLOP-002",
		Severity:   predictiveSeverity(entry.Tier),
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: path, StartLine: imp.line, EndLine: imp.line},
		Message: "Imported package \"" + pkg + "\" is a known high-risk slopsquat target (" + entry.Tier +
			" tier): a name an LLM is likely to hallucinate that was verified unregistered on " + entry.VerifiedAt +
			". Verify it on the official registry before installing or running it.",
		Metadata: map[string]string{
			"package":      pkg,
			"ecosystem":    string(eco),
			"import":       imp.spec,
			"tier":         entry.Tier,
			"pattern":      entry.Pattern,
			"neighbor_of":  entry.NeighborOf,
			"verified_at":  entry.VerifiedAt,
			"feed_version": a.feed.Version(),
			"feed_digest":  a.feed.Digest(),
			"cwe":          "CWE-1357",
		},
	})
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
