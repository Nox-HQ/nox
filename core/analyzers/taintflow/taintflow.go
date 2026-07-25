// Package taintflow is the live analyzer that runs Nox's intraprocedural taint
// engine over discovered source files and turns each un-sanitized source→sink
// flow into a findings.Finding. It is the demonstrable end of the SAST taint
// pipeline: the core/taint catalog supplies the source/sink/sanitizer knowledge,
// core/taint/engine extracts Units and performs the dataflow, and this analyzer
// adapts the resulting Flows to the standard finding shape and rule IDs
// (TAINT-001..006, TAINT-AI-*) shared with the cross-file taint-analysis plugin.
//
// Scope and limits are inherited from the engine and stated honestly on the
// rules and in docs/design/sast-taint.md: Python (primary) and JS/TS
// (best-effort, module-scoped), intraprocedural and straight-line only, no
// cross-file/cross-function flow, no control-flow or alias analysis. It is a
// real, measurable step up from the previous stub — not a full language
// semantics engine.
package taintflow

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/taint"
	"github.com/nox-hq/nox/core/taint/engine"
)

// Analyzer runs the taint engine over source artifacts.
type Analyzer struct {
	cat *taint.Catalog
	eng *engine.StructuralEngine
}

// NewAnalyzer returns a taintflow analyzer backed by the embedded catalog.
func NewAnalyzer() *Analyzer {
	cat := taint.MustDefault()
	return &Analyzer{cat: cat, eng: engine.NewStructuralEngine(cat)}
}

// severityForClass maps a vuln class to the finding severity. Injection classes
// that yield direct RCE/data exfiltration are High; the rest are Medium. The
// engine's structural flow gives medium-to-high confidence (a real def-use path
// to a sink), tempered to Medium confidence because intraprocedural straight-line
// analysis without control-flow can over-report on branchy code.
func severityForClass(class taint.VulnClass) findings.Severity {
	switch class {
	case taint.VulnCommandInjection, taint.VulnSQLInjection, taint.VulnCodeInjection,
		taint.VulnUnsafeDeserialization, taint.VulnSSRF, taint.VulnPromptInjection:
		return findings.SeverityHigh
	default:
		return findings.SeverityMedium
	}
}

// Rules returns one rule per distinct TAINT rule ID present in the catalog, so
// SARIF reporting and rule-listing surface every ID this analyzer can emit. The
// descriptions state the class and the honest intraprocedural limit.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	// Collect distinct (ruleID -> representative sink) across all catalog langs,
	// deterministically.
	type ruleInfo struct {
		class taint.VulnClass
		cwe   string
	}
	byID := map[string]ruleInfo{}
	for _, lang := range a.cat.Languages() {
		for _, s := range a.cat.Sinks(lang) {
			if _, ok := byID[s.RuleID]; !ok {
				byID[s.RuleID] = ruleInfo{class: s.VulnClass, cwe: s.CWE}
			}
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		info := byID[id]
		rs.Add(&rules.Rule{
			ID:          id,
			Version:     "1.0",
			Description: fmt.Sprintf("Untrusted input reaches a %s sink (%s) without sanitization (intraprocedural taint flow)", info.class, info.cwe),
			Severity:    severityForClass(info.class),
			Confidence:  findings.ConfidenceMedium,
			Tags:        []string{"sast", "taint", "injection", string(info.class)},
			Remediation: "A value derived from untrusted input (a request parameter, environment variable, or similar) flows into a dangerous operation in the same function without passing through an appropriate sanitizer. Validate or neutralize the value for this sink's context (parameterized query, argument-vector exec, output escaping, path canonicalization + allow-list) before it reaches the sink. Note: this is intraprocedural analysis — it reasons within one function body only.",
			References: []string{
				"https://cwe.mitre.org/data/definitions/" + cweNumber(info.cwe) + ".html",
				"https://owasp.org/www-community/Injection_Flaws",
			},
			Metadata: map[string]string{"cwe": info.cwe, "vuln_class": string(info.class)},
		})
	}
	return rs
}

// cweNumber strips the "CWE-" prefix for building a MITRE URL; returns the input
// unchanged if it lacks the prefix.
func cweNumber(cwe string) string {
	const p = "CWE-"
	if len(cwe) > len(p) && cwe[:len(p)] == p {
		return cwe[len(p):]
	}
	return cwe
}

// ScanArtifacts runs the taint engine over every Source artifact and returns the
// findings. It is deterministic: artifacts are processed in a stable order and
// the engine sorts flows, so the FindingSet's contents are reproducible.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	// Process in a stable path order so output never depends on discovery order.
	ordered := make([]discovery.Artifact, len(artifacts))
	copy(ordered, artifacts)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	for i := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := ordered[i]
		if art.Type != discovery.Source {
			continue
		}
		lang := lexctx.LangFromPath(art.Path)
		if lang == lexctx.LangUnknown {
			continue // unsupported language: skip (LangFromPath gates the set)
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		a.scanFile(fs, art.Path, lang, content)
	}
	return fs, nil
}

// scanFile extracts units from one file and emits a finding per un-sanitized
// flow, deduplicated per (rule, line) so a repeated sink call in one statement
// does not double-report.
func (a *Analyzer) scanFile(fs *findings.FindingSet, path string, lang lexctx.Lang, content []byte) {
	units := engine.ExtractUnits(path, lang, content)
	// AnalyzeFile runs the whole file at once so it can join a source in one
	// function to a sink reached through a locally-defined helper (SAME-FILE
	// interprocedural flow via function summaries), in addition to the
	// intraprocedural flows Analyze finds. It de-duplicates a source→sink pair
	// reachable both ways, so a purely intraprocedural bug is still reported once.
	flows := a.eng.AnalyzeFile(units)
	for j := range flows {
		fs.Add(a.toFinding(&flows[j]))
	}
}

// toFinding maps a Flow to a findings.Finding using the sink's RuleID/CWE and a
// source→sink message, located at the sink call. The finding carries triage
// metadata: the vuln class, the source kind and variable, the sink call, and the
// source line.
func (a *Analyzer) toFinding(flow *taint.Flow) findings.Finding {
	sink := flow.Sink
	var msg string
	if len(flow.Via) > 0 {
		// Cross-function flow: name the intermediate helper(s) so triage can follow
		// the path from the caller's source through the summarized helper(s) to the
		// sink.
		msg = fmt.Sprintf(
			"Untrusted input (%s via %q) reaches %s sink %q through %s without sanitization — %s.",
			flow.Source.Kind, flow.SourceVar, sink.VulnClass, sink.Call,
			viaPath(flow.Via), sink.CWE,
		)
	} else {
		msg = fmt.Sprintf(
			"Untrusted input (%s via %q) reaches %s sink %q without sanitization — %s.",
			flow.Source.Kind, flow.SourceVar, sink.VulnClass, sink.Call, sink.CWE,
		)
	}
	meta := map[string]string{
		"cwe":         sink.CWE,
		"vuln_class":  string(sink.VulnClass),
		"sink":        sink.Call,
		"source_kind": string(flow.Source.Kind),
		"source_call": flow.Source.Call,
		"source_var":  flow.SourceVar,
		"source_line": fmt.Sprintf("%d", flow.SourceLine),
		"function":    flow.FuncName,
	}
	if len(flow.Via) > 0 {
		meta["interprocedural"] = "true"
		meta["via"] = strings.Join(flow.Via, " -> ")
	}
	// For a role-aware prompt-injection (LLM) sink, record the chat role the
	// tainted value lands in so the verdict is auditable: "system"/"developer" is
	// the trust-inverting injection this keeps; a user-role placement behind a
	// static system message was already suppressed upstream and never reaches here.
	if flow.SinkRole != "" {
		meta["sink_role"] = flow.SinkRole
	}
	return findings.Finding{
		RuleID:     sink.RuleID,
		Severity:   severityForClass(sink.VulnClass),
		Confidence: findings.ConfidenceMedium,
		Location: findings.Location{
			FilePath:  flow.FilePath,
			StartLine: flow.SinkLine,
			EndLine:   flow.SinkLine,
		},
		Message:  msg,
		Metadata: meta,
	}
}

// viaPath renders a cross-function path for a finding message, e.g.
// `helper "wrap" -> "run"` for a two-hop chain.
func viaPath(via []string) string {
	quoted := make([]string, len(via))
	for i, v := range via {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return "helper " + strings.Join(quoted, " -> ")
}
