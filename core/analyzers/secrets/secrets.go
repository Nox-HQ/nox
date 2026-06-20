// Package secrets implements pattern-based secret detection. It wraps the
// core/rules engine with a set of built-in rules that detect common secret
// patterns such as AWS keys, GitHub tokens, private key headers, and generic
// API key assignments in source files and configuration.
package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// isGeneratedSecretsPath reports whether a path is a lock file, checksum,
// minified bundle or tool-state file that the secrets analyzer should skip
// wholesale. It matches each glob in generatedFileIgnorePatterns against both
// the full (slash-normalised) path and its basename, mirroring the per-rule
// matching in core/rules/engine.go.
func isGeneratedSecretsPath(path string) bool {
	norm := filepath.ToSlash(path)
	base := filepath.Base(norm)
	for _, pattern := range generatedFileIgnorePatterns {
		if matched, _ := filepath.Match(pattern, norm); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}

// Analyzer wraps a rules.Engine pre-loaded with secret detection rules.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in secret detection rules loaded
// programmatically. The rules use regex matching and apply to all file types.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	for _, r := range builtinSecretRules() {
		rs.Add(r)
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// EntropyOverrides holds optional overrides for entropy-based rule thresholds.
// Zero values mean "keep rule defaults".
type EntropyOverrides struct {
	// Threshold overrides SEC-161 entropy_threshold.
	Threshold float64
	// HexThreshold overrides SEC-163 entropy_threshold.
	HexThreshold float64
	// Base64Threshold overrides SEC-162 entropy_threshold.
	Base64Threshold float64
	// RequireContext overrides the require_context metadata on SEC-162/163.
	// nil means keep rule defaults.
	RequireContext *bool
}

// ApplyEntropyOverrides updates entropy rule metadata based on config
// overrides. This must be called before scanning.
func (a *Analyzer) ApplyEntropyOverrides(o EntropyOverrides) {
	rulesList := a.engine.Rules().Rules()
	for i := range rulesList {
		r := rulesList[i]
		if r.MatcherType != "entropy" {
			continue
		}
		if r.Metadata == nil {
			r.Metadata = make(map[string]string)
		}
		switch r.ID {
		case "SEC-161":
			if o.Threshold > 0 {
				r.Metadata["entropy_threshold"] = strconv.FormatFloat(o.Threshold, 'f', -1, 64)
			}
		case "SEC-162":
			if o.Base64Threshold > 0 {
				r.Metadata["entropy_threshold"] = strconv.FormatFloat(o.Base64Threshold, 'f', -1, 64)
			}
			if o.RequireContext != nil {
				r.Metadata["require_context"] = strconv.FormatBool(*o.RequireContext)
			}
		case "SEC-163":
			if o.HexThreshold > 0 {
				r.Metadata["entropy_threshold"] = strconv.FormatFloat(o.HexThreshold, 'f', -1, 64)
			}
			if o.RequireContext != nil {
				r.Metadata["require_context"] = strconv.FormatBool(*o.RequireContext)
			}
		}
	}
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any secret-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// ScanArtifacts reads each artifact file from disk, scans it for secrets, and
// collects all findings into a deduplicated FindingSet. If any artifact cannot
// be read, scanning stops and the error is returned.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, artifact := range artifacts {
		// Skip lock files, checksums, minified bundles and tool state dirs
		// wholesale: their content-addressed hashes match both the entropy
		// rules and the provider-key regexes, producing thousands of false
		// positives. This mirrors gitleaks / trufflehog / detect-secrets.
		if isGeneratedSecretsPath(artifact.Path) {
			continue
		}

		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		for i := range results {
			fs.Add(results[i])
		}

		// Scan decoded base64/hex content for encoded secrets.
		decodedResults := DecodeAndScan(content, artifact.Path, a.engine)
		for i := range decodedResults {
			fs.Add(decodedResults[i])
		}
	}

	fs.Deduplicate()
	return fs, nil
}
