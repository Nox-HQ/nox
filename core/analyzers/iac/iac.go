// Package iac implements Infrastructure-as-Code security scanning. It wraps
// the core/rules engine with built-in rules that detect common IaC
// misconfigurations in Dockerfiles, Terraform files, and Kubernetes manifests.
package iac

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer wraps a rules.Engine pre-loaded with IaC security rules.
type Analyzer struct {
	engine *rules.Engine
	// reasoning receives a claim for every finding this analyzer decided by
	// parsing the document rather than by matching text. Nil unless a caller
	// asked for evidence, which keeps recording free when nobody did.
	reasoning *reasoning.Store
}

// NewAnalyzer creates an Analyzer with built-in IaC security rules loaded
// programmatically. Rules are scoped to specific file types via FilePatterns.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	iacRules := builtinIaCRules()
	for i := range iacRules {
		rs.Add(&iacRules[i])
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// RecordReasoningTo directs this analyzer's claims at store.
//
// The IaC family had no evidence seam at all until the structural path existed,
// and that was the honest state of things: every IAC finding rested on a
// pattern match, so the only claim it could have filed is the bare observation
// the scan already records. There was nothing to say. There is now.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// recordStructuralClaims files what parsing established about each finding.
//
// The claim is KindStatic, and that is the point of the whole feature: "the
// resource was parsed and sets no BucketEncryption" is static analysis, while
// "no pattern matched inside a span I guessed by indentation" is a heuristic
// however carefully the pattern was written. It is the first claim in this
// family that can lift a finding off the heuristic floor honestly.
//
// # Why refutations are not recorded here
//
// The structural path also refutes — a resource whose property the pattern
// could not see is not reported at all — and none of those produce a claim,
// deliberately. A refutation in this model attaches to a candidate, and there
// is no candidate: the finding was never created. That is different from the
// secrets refiners, which drop a candidate that existed and must say why. What
// is lost is visible in the finding count and in nothing else, which is the
// same place a false positive's removal has always been visible.
func (a *Analyzer) recordStructuralClaims(path string, fs []findings.Finding) {
	if a.reasoning == nil {
		return
	}
	for i := range fs {
		claim := fs[i].Metadata[rules.StructuralClaimKey]
		if claim == "" {
			continue
		}
		subject := reasoning.Candidate(fs[i].RuleID, path,
			fs[i].Location.StartLine, fs[i].Location.StartColumn)
		a.reasoning.Support(subject, evidence.KindStatic, "nox-scan", "iac", claim, nil)
	}
}

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any IaC-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	results, err := a.engine.ScanFile(path, content)
	if err != nil {
		return nil, err
	}
	out := dropArtifactsWhenAlways(results, content)
	a.recordStructuralClaims(path, out)
	return out, nil
}

// dropArtifactsWhenAlways removes IAC-348 findings whose `when: always` sits
// inside an `artifacts:` block.
//
// The rule matches the two words with a bare pattern, but everything it says
// is about JOB EXECUTION: "CI job runs regardless of previous failures", and a
// remediation warning that running deployment jobs after test failures can push
// broken code to production. Under `artifacts:` the same words mean upload the
// artifacts even when the job failed — which for a scanner is the entire point,
// since the run you most want the SARIF from is the one that failed the gate.
// nox's own GitLab example was flagged for doing the right thing.
//
// Dropped rather than downgraded, for the same reason as the Ansible rules on
// GitHub Actions files: a lower-severity finding still puts a rule in front of
// an operator that could not apply here.
//
// Block membership is decided by indentation — the nearest enclosing key at a
// shallower indent — which is enough for the mapping shapes CI files use and
// needs no YAML parser on this path.
func dropArtifactsWhenAlways(in []findings.Finding, content []byte) []findings.Finding {
	if len(in) == 0 {
		return in
	}
	var lines []string
	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-348" {
			kept = append(kept, f)
			continue
		}
		if lines == nil {
			lines = strings.Split(string(content), "\n")
		}
		if enclosingKey(lines, f.Location.StartLine) == "artifacts" {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// enclosingKey returns the mapping key that encloses a 1-based line, or "" if
// the line is top-level or out of range.
func enclosingKey(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
	target := indent(lines[line-1])
	for i := line - 2; i >= 0; i-- {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indent(l) >= target {
			continue
		}
		key, _, found := strings.Cut(trimmed, ":")
		if !found {
			return ""
		}
		return strings.TrimSpace(strings.TrimPrefix(key, "- "))
	}
	return ""
}

// ScanArtifacts reads each artifact file from disk, scans it for IaC
// misconfigurations, and collects all findings into a deduplicated FindingSet.
// GitHub Actions workflow findings receive a context-aware post-pass that
// downgrades well-known false positives (ephemeral test DB credentials,
// permissions paired with their justifying consumer action).
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	var collected []findings.Finding
	for _, artifact := range artifacts {
		// Honour cancellation between artifacts — see the note in the secrets
		// analyzer: nothing else in this loop consults ctx.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		collected = append(collected, results...)
	}

	// GitHub Actions context downgrades are applied by the scan pipeline across
	// EVERY analyzer's output (core/scan.go), not just IaC's. Applying them a
	// second time here was redundant, and — before finding metadata was copied
	// per-finding — the second pass re-wrote a shared map and contaminated
	// unrelated findings. The pipeline is the single place they are applied.
	for i := range collected {
		fs.Add(collected[i])
	}

	fs.Deduplicate()
	return fs, nil
}
