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
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
)

// isGeneratedSecretsPath reports whether a path is a lock file, checksum,
// minified bundle or tool-state file that the secrets analyzer should skip
// wholesale. It matches each glob in generatedFileIgnorePatterns against both
// the full (slash-normalised) path and its basename, mirroring the per-rule
// matching in core/rules/engine.go.
//
// # Directory patterns match at any depth
//
// A pattern of the form "dir/*" names a tool-state DIRECTORY, and the intent is
// that nothing inside it is scanned. filepath.Match cannot express that: its
// "*" does not cross a separator and the pattern is anchored at the start, so
// ".claude/*" matched .claude/settings.json and missed
// .claude/worktrees/agent-x/.nox/baseline.json entirely.
//
// That was not theoretical. Scanning a repository with git worktrees under
// .claude/ produced 107 high-severity "Cloudflare API Token" findings, every
// one of them a SHA-256 fingerprint inside nox's OWN baseline files — the tool
// reporting its own output as credentials, in the one directory the list
// already claimed to exclude. Every directory entry had the same hole:
// .nox, .claude, .roady, .cursor, .continue, .vex, testdata.
//
// So directory patterns are matched by path SEGMENT. Anything under a named
// directory is skipped wherever that directory sits.
func isGeneratedSecretsPath(path string) bool {
	norm := filepath.ToSlash(path)
	base := filepath.Base(norm)
	segments := strings.Split(norm, "/")

	for _, pattern := range generatedFileIgnorePatterns {
		if dir, ok := strings.CutSuffix(pattern, "/*"); ok {
			for _, seg := range segments[:max(0, len(segments)-1)] {
				if seg == dir {
					return true
				}
			}
			continue
		}
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
	// spec maps rule ID → specificity tier, used to collapse the
	// provider-rule-vs-generic-rule pileup on a single token (see dedup.go).
	// Built once at construction from the loaded rule set's structure.
	spec map[string]int
	// reasoning receives a refuting claim for every candidate this analyzer
	// drops. Nil by default and nil for every existing caller, which is what
	// keeps recording free when nobody asked for it: reasoning.Store is
	// nil-safe, so the call sites below are unconditional and there is no
	// second code path that could drift from the first.
	reasoning *reasoning.Store
}

// RecordReasoningTo directs this analyzer's refutations at store.
//
// It is a setter rather than a NewAnalyzer parameter because the reasoning
// store is scan-scoped while the analyzer is constructed in three places, one
// of them the rule catalog, which has no scan and wants no store.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// NewAnalyzer creates an Analyzer with built-in secret detection rules loaded
// programmatically. The rules use regex matching and apply to all file types.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	for _, r := range builtinSecretRules() {
		rs.Add(r)
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
		spec:   specificityByRule(rs.Rules()),
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
		// Honour cancellation between artifacts. A scan over a large tree can
		// run for a long time; without this the analyzer would keep reading
		// files after the caller's context was cancelled or its deadline
		// passed, since nothing inside the loop touches ctx.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

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

		// Collapse the provider-rule-vs-generic-rule pileup: when several
		// secret rules match the SAME token span on a line, keep only the
		// most-specific (provider) finding and drop the generic entropy/keyword
		// duplicates. This is the dominant precision drag on real secrets — one
		// GitHub/Slack/Stripe token otherwise emits 5-8 findings.
		results = dedupBySpecificity(results, a.spec, content)

		// Drop matches that fall inside an embedded data blob (a base64 SVG, a
		// data: URI) in a source file — a 32-char run inside such a blob is never
		// a real credential and is the dominant secret false-positive class. This
		// only fires on lexable source (Python/JS/TS); comments and ordinary
		// string literals (where a real hardcoded secret lives) are kept.
		//
		// Also drop obvious documentation placeholders ("your-api-key-here",
		// "changeme", "<...>", "postgres://USER:PASSWORD@host", all-x/all-zero
		// masks) — these are not live credentials and mirror the
		// gitleaks/trufflehog/detect-secrets example allowlists.
		lang := lexctx.LangFromPath(artifact.Path)
		for i := range results {
			// Every drop below records WHY before it drops. The reason is known
			// only here, and a refiner that discards it produces a result
			// indistinguishable from one that had nothing to discard — which is
			// precisely the failure the refutation corpus exists to catch and
			// the reasoning store exists to make auditable.
			candidate := reasoning.Candidate(results[i].RuleID, artifact.Path,
				results[i].Location.StartLine, results[i].Location.StartColumn)

			if inEmbeddedBlob(lang, content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the match lies inside an embedded data blob (base64 or data: URI) in lexable source, not in code or a string literal")
				continue
			}
			// inEmbeddedBlob consults lexctx, which reports LangUnknown for
			// markup and stylesheets — so an inline `data:` URI in .html/.css/.md
			// was never covered. The marker is unambiguous in raw bytes.
			if inDataURIPayload(content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the match lies inside a data: URI payload")
				continue
			}
			// Drop a bare provider-prefix match with no token body — the literal
			// `"glpat-"` or the `sk_live_` inside a `// prefix (ghp_, sk_live_, …)`
			// comment that a pattern-vocabulary file must name. A live credential
			// always carries a 20+ char high-entropy body; a match that is only the
			// prefix is a reference, never a leaked secret. This is deliberately
			// narrower than dropping every comment/string match: a FULL token in a
			// comment (a genuinely leaked credential) is still kept, because its
			// matched value is more than the bare prefix.
			if isBareProviderPrefix(content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the match is a bare provider prefix with no token body; a live credential always carries a 20+ character high-entropy body")
				continue
			}
			if isPlaceholderFinding(content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the matched VALUE is a documentation placeholder, read from the literal rather than inferred from the identifier")
				continue
			}
			// A secret shown inside a display-text HTML/JSX attribute
			// (`placeholder=`, `aria-label=`, `title=`) is the instruction
			// telling a user what to paste, not key material the repository
			// holds.
			if inDisplayTextAttribute(content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"the match sits in a display-text HTML/JSX attribute, so it is the instruction telling a user what to paste, not key material this repository holds")
				continue
			}
			// An assignment-shaped config-field rule that matched inside a
			// comment found prose describing a field, not a field being
			// assigned. Provider rules are untouched — a full token in a
			// comment is a real leak.
			if dropConfigFieldRuleInComment(lang, content, &results[i]) {
				a.refute(candidate, evidence.KindStatic,
					"an assignment-shaped rule matched entirely within a comment region, so there is no assignment for it to have found")
				continue
			}
			a.corroborate(candidate, content, &results[i])
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

// isPlaceholderFinding reports whether a finding's matched value is an obvious
// documentation placeholder that should be dropped. The finding may carry the
// matched value in Metadata; otherwise we reconstruct it from content using the
// finding's byte offsets (start..end via the location's line/column).
func isPlaceholderFinding(content []byte, f *findings.Finding) bool {
	if f.Metadata != nil {
		if v, ok := f.Metadata["match"]; ok && v != "" {
			return isPlaceholderValue(v)
		}
	}
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start || end > len(content) {
		return false
	}
	if isPlaceholderValue(string(content[start:end])) {
		return true
	}
	// Credential-aware DSN rules (SEC-073/074/076 for postgres, mysql, mongodb,
	// redis URLs) match the userinfo span, so a placeholder signal — a
	// user:password template like `postgres://USER:PASSWORD@host` — can sit in
	// the rest of the line rather than the matched span. Inspect the whole source
	// line for a credentials-in-URL placeholder.
	if isURLCredentialPlaceholderLine(lineOf(content, f.Location.StartLine)) {
		return true
	}
	return false
}

// lineOf returns the 1-based source line (without the trailing newline) from
// content, or "" if the line number is out of range.
func lineOf(content []byte, line int) string {
	if line < 1 {
		return ""
	}
	start := lexctx.LineColToOffset(content, line, 1)
	end := lexctx.LineColToOffset(content, line+1, 1)
	if end <= start || end > len(content) {
		end = len(content)
	}
	return string(content[start:end])
}

// inEmbeddedBlob reports whether a finding's location sits inside a data-blob
// string literal in lexable source, using the finding's reported line/column.
func inEmbeddedBlob(lang lexctx.Lang, content []byte, f *findings.Finding) bool {
	if lang == lexctx.LangUnknown {
		return false
	}
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start {
		end = start + 1
	}
	return lexctx.InDataBlob(lang, content, start, end)
}

// refute records why a candidate was dropped.
//
// It exists so the six call sites above read as one line of intent each, and
// so the provenance is written once. A refiner that had to spell out its own
// source and tool at every drop would eventually spell one of them differently,
// and a claim attributed to a producer that does not exist is a claim no
// Authority can check.
func (a *Analyzer) refute(subject evidence.Subject, kind evidence.Kind, statement string) {
	a.reasoning.Refute(subject, kind, "nox-scan", "secrets", statement)
}

// corroborate records what the analyzer actually VERIFIED about a value it is
// about to report.
//
// This is the positive counterpart of the refiners above, and it exists
// because of the same historical bug they do. ENRICH-004 matched the NAME of
// an assignment and never looked at the value; the refiners fixed that by
// dropping placeholders. But a finding that survives has ALSO been inspected —
// its value was read, it carried a recognised provider format, it was not a
// placeholder — and none of that was written down. The ledger could say why nox
// stopped believing something and never what it had actually checked before
// believing it.
//
// # What this deliberately does not do
//
// It does not raise confidence, and it was worth discovering that before
// claiming otherwise. Aggregation takes the STRONGEST supporting claim, and
// every claim recorded here is a heuristic: a regex matched a prefix, a value
// did not look like a placeholder. Three heuristics are still a heuristic, and
// the independence promotion cannot apply either, since all of these come from
// one producer — counting them as independent corroboration would be the "one
// project scanning itself a hundred times" fallacy with the numbers changed.
//
// So this improves EXPLANATION, not confidence. What would move confidence is
// evidence of a different kind: several providers encode a checksum in the
// token itself, and verifying one is deterministic rather than heuristic. That
// is a real and worthwhile next step, and it needs a verifiable test vector
// before it is written — shipping unverified checksum logic would put false
// deterministic claims in the ledger, which is worse than the silence it
// replaces.
func (a *Analyzer) corroborate(subject evidence.Subject, content []byte, f *findings.Finding) {
	if a.reasoning == nil {
		return
	}
	value := matchedValue(content, f)
	if value == "" {
		return
	}
	// A verified checksum is the one thing here that is not a heuristic. It is
	// recorded at KindStatic and everything else at KindHeuristic, and that
	// difference is the whole reason it is worth computing: it is the first
	// claim in this pipeline that can lift a finding off the floor honestly,
	// rather than by weighting a pattern match more heavily than a pattern
	// match deserves.
	//
	// A FAILED checksum is evidence too, and in the other direction: a
	// ghp_-prefixed string of exactly the right length whose CRC32 does not
	// agree is deterministically not a GitHub token. It is recorded and NOT
	// acted on — nothing is dropped here — because a refutation that changes
	// output must pass Gate A first.
	//
	// A value the check does not apply to produces no claim at all. "I cannot
	// check this" is not "I checked this and it failed".
	if consistent, applicable := verifyGitHubToken(value); applicable {
		if consistent {
			a.reasoning.Support(subject, evidence.KindStatic, "nox-scan", "secrets",
				"the token's embedded CRC32 checksum verifies, so the value is internally consistent as a credential of this provider", nil)
		} else {
			a.reasoning.Refute(subject, evidence.KindStatic, "nox-scan", "secrets",
				"the token carries a provider format and length but its embedded CRC32 checksum does not verify, so it is not a credential of that provider")
		}
	}

	// The second deterministic signal: a JWT's structure is offline-verifiable.
	// The header base64url-decodes to a JSON object naming a signing algorithm,
	// which no string that merely matches the loose eyJ....eyJ.... pattern will
	// do by accident. It establishes that this IS a JWT, never that its
	// signature is valid — that needs a key, and nox does not want one. A value
	// shaped like a JWT whose header does not decode is deterministically not
	// one, the same refutation the checksum makes for GitHub.
	if consistent, applicable := verifyJWT(value); applicable {
		if consistent {
			a.reasoning.Support(subject, evidence.KindStatic, "nox-scan", "secrets",
				"the value decodes as a JWT: its header is base64url-encoded JSON naming a signing algorithm, so it is a real token rather than a lookalike", nil)
		} else {
			a.reasoning.Refute(subject, evidence.KindStatic, "nox-scan", "secrets",
				"the value is shaped like a JWT but its header does not base64url-decode to a JSON object with an algorithm, so it is not one")
		}
	}

	if prefix, ok := recognisedProviderPrefix(strings.TrimLeft(value, `"'`)); ok {
		a.support(subject, "the value carries the recognised provider prefix "+prefix+
			" and a token body, so it is not a bare vocabulary reference")
	}
	// The value was READ, and it is not a placeholder. That is the precise
	// check ENRICH-004 never performed, so recording that it ran and passed is
	// what makes this finding's ledger different from that rule's.
	a.support(subject, "the matched value was inspected and is not a documentation placeholder")
}

// support records a corroborating claim about a candidate that survived.
func (a *Analyzer) support(subject evidence.Subject, statement string) {
	a.reasoning.Support(subject, evidence.KindHeuristic, "nox-scan", "secrets", statement, nil)
}
