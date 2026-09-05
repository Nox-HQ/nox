package iac

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// embeddedManifest is a Kubernetes manifest found inside a YAML block scalar,
// together with the line in the outer file where its first line sits.
type embeddedManifest struct {
	content    []byte
	lineOffset int // outer-file line number of content's line 1
}

// blockScalarRE matches a mapping key introducing a literal or folded block
// scalar: `manifest: |`, `template: >-`, `content: |2+` and so on.
var blockScalarRE = regexp.MustCompile(`^(\s*)[\w.\-/]+\s*:\s*[|>][-+0-9]*\s*$`)

// looksLikeK8sManifest reports whether s carries both of the keys that make a
// Kubernetes document. Deliberately cheap and textual: this decides whether to
// spend a second scan on a string, not whether a finding is real.
func looksLikeK8sManifest(s string) bool {
	return strings.Contains(s, "apiVersion:") && strings.Contains(s, "kind:")
}

// extractEmbeddedManifests returns the Kubernetes manifests embedded in YAML
// block scalars within content.
//
// Absence rules and pattern rules disagreed about these. A pattern rule is a
// regex over the whole file, so it matches inside a block scalar without
// knowing the string is there. An absence rule bounds itself to a YAML
// document, and the block scalar's contents are a string VALUE of the outer
// document rather than a document of their own — so it never looked inside,
// and reported nothing.
//
// Reporting nothing is the problem. A pattern rule that misses says nothing and
// claims nothing; an absence rule that never evaluates produces the same output
// as a clean result. Every workload deployed through a wrapper that embeds its
// manifest — RollOps RolloutConfig, Argo CD Application, a Helm template
// rendered into a ConfigMap, a Flux patch — had its hardening checks silently
// skipped while the scan reported clean.
//
// Only the absence rules are re-run over what this returns. Pattern rules
// already match inside the block, so running them again would report every
// pattern finding twice — the double-report that retiring IAC-374 just removed.
func extractEmbeddedManifests(content []byte) []embeddedManifest {
	if !bytes.Contains(content, []byte("apiVersion:")) {
		return nil
	}

	var out []embeddedManifest
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), maxEmbeddedBytes)

	var (
		lineNo      int
		inBlock     bool
		blockIndent int
		bodyIndent  int
		startLine   int
		body        []string
	)

	flush := func() {
		if inBlock && len(body) > 0 {
			joined := strings.Join(body, "\n") + "\n"
			if looksLikeK8sManifest(joined) {
				out = append(out, embeddedManifest{content: []byte(joined), lineOffset: startLine})
			}
		}
		inBlock, body = false, nil
	}

	for sc.Scan() {
		lineNo++
		line := sc.Text()

		if inBlock {
			trimmed := strings.TrimLeft(line, " \t")
			indent := len(line) - len(trimmed)
			// A blank line belongs to the block; it carries no indentation to
			// judge and dropping it would corrupt the reconstructed document.
			if trimmed == "" {
				body = append(body, "")
				continue
			}
			if bodyIndent < 0 {
				bodyIndent = indent
				startLine = lineNo
			}
			if indent < bodyIndent || indent <= blockIndent {
				flush()
				// fall through: this line may itself open a new block
			} else {
				body = append(body, line[bodyIndent:])
				continue
			}
		}

		if m := blockScalarRE.FindStringSubmatch(line); m != nil {
			inBlock = true
			blockIndent = len(m[1])
			bodyIndent = -1
			body = nil
		}
	}
	flush()
	return out
}

// maxEmbeddedBytes bounds a single embedded document. A block scalar is
// operator-authored config, not input, but an unbounded scanner buffer on a
// pathological file is a denial of service with extra steps.
const maxEmbeddedBytes = 1 << 20

// scanEmbedded runs the absence rules over each manifest embedded in content
// and rewrites the reported lines back into the outer file.
// already keys a finding by the fact it asserts: the same rule, at the same
// line of the same file, is the same fact however it was reached.
type seenKey struct {
	rule string
	line int
}

func (a *Analyzer) scanEmbedded(path string, content []byte, outer []findings.Finding) ([]findings.Finding, error) {
	if a.absence == nil {
		return nil, nil
	}

	// Some absence rules already fire on the outer file: their anchor is raw
	// text, so `kind: Deployment` inside a block scalar matches, and a
	// span of "file" (or a yaml-doc span that swallows the block) then looks
	// for the hardening property across the whole thing. IAC-176 and IAC-183
	// both do this. Re-reporting them from the extracted document would double
	// every one of those — the defect retiring IAC-374 just removed, reintroduced
	// by the fix for the opposite problem.
	seen := make(map[seenKey]struct{}, len(outer))
	for i := range outer {
		seen[seenKey{outer[i].RuleID, outer[i].Location.StartLine}] = struct{}{}
	}

	var out []findings.Finding
	for _, em := range extractEmbeddedManifests(content) {
		got, err := a.absence.ScanFile(path, em.content)
		if err != nil {
			return nil, err
		}
		for i := range got {
			// The finding's line is relative to the extracted document. Shift
			// it so an operator opening the file at that line sees the
			// resource the rule is talking about, not an unrelated one.
			got[i].Location.StartLine += em.lineOffset - 1
			if got[i].Location.EndLine > 0 {
				got[i].Location.EndLine += em.lineOffset - 1
			}
			// Column offsets do not survive the re-indent, and a wrong column
			// is worse than none.
			got[i].Location.StartColumn = 0
			got[i].Location.EndColumn = 0
			if got[i].Metadata == nil {
				got[i].Metadata = map[string]string{}
			}
			got[i].Metadata["embedded_manifest"] = "true"

			k := seenKey{got[i].RuleID, got[i].Location.StartLine}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, got[i])
		}
	}
	return out, nil
}

// absenceRuleSet returns the absence-matcher rules from rs.
func absenceRuleSet(rs []rules.Rule) *rules.RuleSet {
	out := rules.NewRuleSet()
	var n int
	for i := range rs {
		if rs[i].MatcherType != "absence" {
			continue
		}
		out.Add(&rs[i])
		n++
	}
	if n == 0 {
		return nil
	}
	return out
}
