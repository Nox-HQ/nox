// Package data implements pattern-based data sensitivity detection. It wraps
// the core/rules engine with a set of built-in rules that detect common PII
// patterns such as email addresses, social security numbers, credit card
// numbers, and other personally identifiable information in source files and
// configuration.
package data

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer wraps a rules.Engine pre-loaded with data sensitivity detection rules.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in data sensitivity detection
// rules loaded programmatically. The rules use regex matching and apply to all
// file types.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	builtins := builtinDataRules()
	for _, r := range builtins {
		rs.Add(r)
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any data sensitivity findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	got, err := a.engine.ScanFile(path, content)
	if err != nil {
		return nil, err
	}
	got = dropDigitsInsideDecimals(got, content)
	return dropPublishedContactEmails(got, path, content), nil
}

// packageManifests name a project's own authors and maintainers. An address in
// one of those fields is published to a registry as the contact point for the
// package.
var packageManifests = map[string]bool{
	"pyproject.toml": true, "setup.py": true, "setup.cfg": true,
	"package.json": true, "composer.json": true, "Cargo.toml": true,
	"pom.xml": true, "build.gradle": true, "Gemfile": true,
}

// dropPublishedContactEmails removes DATA-001 findings on addresses that exist
// in order to be read.
//
// DATA-001 reports PII hard-coded in source and advises "remove or externalize
// PII data". For an address the project publishes as its own contact point that
// advice is wrong, and the finding is not describing a data-handling failure.
//
// Measured on the pinned corpus: 969 findings over just 177 distinct addresses,
// 716 of them `support@crewai.com`. Every one was published contact
// information -- 42.9% inside a `mailto:` URI, 23.6% in a package manifest's
// author field, the rest OpenAPI `contact:` blocks and documentation support
// sections, including translated copies of the same page.
//
// Two structural exclusions, neither a judgement call:
//
//   - an address inside a `mailto:` URI exists so a reader can write to it;
//   - an address in a package manifest is published to the registry with the
//     package.
//
// NOT excluded, and left deliberately: an address in documentation prose, and
// an OpenAPI `contact:` block. Both are also published, but recognising them
// needs block context rather than the line, and whether nox should report
// e-mail in docs at all is a question about the rule's purpose rather than a
// defect in its evidence.
func dropPublishedContactEmails(got []findings.Finding, path string, content []byte) []findings.Finding {
	if len(got) == 0 {
		return got
	}
	manifest := packageManifests[filepath.Base(path)]
	lines := strings.Split(string(content), "\n")
	out := got[:0]
	for _, f := range got {
		if f.RuleID == "DATA-001" {
			ln := f.Location.StartLine
			if ln >= 1 && ln <= len(lines) {
				lower := strings.ToLower(lines[ln-1])
				if strings.Contains(lower, "mailto:") {
					continue
				}
				if manifest && contactField(lower) {
					continue
				}
			}
		}
		out = append(out, f)
	}
	return out
}

// contactField reports whether a manifest line names an author, maintainer or
// contact rather than some other use of an address.
func contactField(lowerLine string) bool {
	for _, k := range []string{"author", "maintainer", "contact", "email", "publisher", "owner"} {
		if strings.Contains(lowerLine, k) {
			return true
		}
	}
	return false
}

// numericIdentityRules report a digit run as an identity document. A run that
// is the fractional part of a decimal literal is not one, whatever its shape.
var numericIdentityRules = map[string]bool{
	"DATA-003": true, // payment card number
}

// dropDigitsInsideDecimals removes findings whose matched digit run is the
// fractional part of a decimal number.
//
// DATA-003's pattern is anchored with `\b`, and `.` is not a word character, so
// the digits after a decimal point are word-bounded and match a card prefix
// whenever the leading digit happens to be 4, 5, 3 or 6. Measured on the pinned
// corpus: 560 findings, and ALL 560 were floats -- embedding vectors and
// notebook output such as `Similarity: 0.6522269248962402`, each reported at
// HIGH severity as a Discover card.
//
// The Luhn check in isPaymentCardNumber removes 90.7% of those, which is the
// rate chance predicts; the 52 that pass it are still floats. So the checksum
// and this filter are both needed, and neither is a heuristic: a real card in
// source is a quoted digit literal, never the fractional part of a float.
//
// (The card networks' published test numbers live in card_number_test.go, which
// the self-scan excludes. Spelling one out here would make this comment a
// DATA-003 finding in nox's own tree -- the rule working correctly on the
// explanation of itself.)
//
// This lives here rather than in the pattern because RE2 has no lookbehind, and
// rather than in ValidateMatch because that predicate sees only the matched
// text and this question is about the byte before it.
func dropDigitsInsideDecimals(got []findings.Finding, content []byte) []findings.Finding {
	if len(got) == 0 {
		return got
	}
	lineStarts := []int{0}
	for i, b := range content {
		if b == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	out := got[:0]
	for _, f := range got {
		if numericIdentityRules[f.RuleID] && precededByDecimalPoint(content, lineStarts, f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// precededByDecimalPoint reports whether the byte before a finding's match is a
// `.` that follows a digit -- i.e. the match is the fractional part of a number
// rather than a standalone run. A leading `.` with no digit before it is a file
// extension or an ellipsis, and says nothing either way.
func precededByDecimalPoint(content []byte, lineStarts []int, f findings.Finding) bool {
	ln, col := f.Location.StartLine, f.Location.StartColumn
	if ln < 1 || ln > len(lineStarts) || col < 1 {
		return false
	}
	off := lineStarts[ln-1] + col - 1
	if off < 2 || off > len(content) {
		return false
	}
	return content[off-1] == '.' && content[off-2] >= '0' && content[off-2] <= '9'
}

// ScanArtifacts reads each artifact file from disk, scans it for sensitive
// data patterns, and collects all findings into a deduplicated FindingSet. If
// any artifact cannot be read, scanning stops and the error is returned.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

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

		for i := range results {
			fs.Add(results[i])
		}
	}

	fs.Deduplicate()
	return fs, nil
}
