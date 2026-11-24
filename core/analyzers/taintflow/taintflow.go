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
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/analyzers/flowunits"
	"github.com/nox-hq/nox/core/callgraph"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/taint"
	"github.com/nox-hq/nox/core/taint/engine"
)

// Analyzer runs the taint engine over source artifacts.
type Analyzer struct {
	cat *taint.Catalog
	eng *engine.StructuralEngine
	// reasoning receives the refutations. Nil until asked for, and every
	// recording call is nil-safe, so the scan path below never branches on
	// whether anybody wanted them.
	reasoning *reasoning.Store
	// optIn holds the rule IDs of opt-in sinks this scan enabled; a flow into
	// an opt-in sink whose rule is not here is not reported.
	optIn map[string]bool
}

// EnableOptIn turns on the opt-in taint rules named in ids (scan.rules.enable),
// the same switch the regex rules use.
func (a *Analyzer) EnableOptIn(ids []string) {
	a.optIn = map[string]bool{}
	for _, id := range ids {
		a.optIn[id] = true
	}
}

// RecordReasoningTo directs this analyzer's refutations at store.
//
// The taint engine performs the most sophisticated refinement in nox —
// class-precise sanitizer clearing, argument-shape analysis — and recorded none
// of it. The stage accounting reported TAINT as refuting nothing on every
// corpus, which was true of the ledger and false of the engine.
//
// That gap has cost real defects: an argv exemption that silenced shell sinks
// in five of six cases, a same-statement sanitizer invisible in every language
// but Go. In each, the evidence needed to notice was computed and thrown away.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

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
	case taint.VulnTrustBoundary, taint.VulnLogInjection:
		// The value is not executed or interpreted where it lands; the risk
		// is later code trusting what the session holds, or a reader trusting
		// a log entry the input forged.
		return findings.SeverityLow
	case taint.VulnArgumentInjection:
		// One argument of an argv exec, no shell: at worst read as an option.
		// Explicitly below command injection, which reports as high.
		return findings.SeverityMedium
	default:
		return findings.SeverityMedium
	}
}

// Rules returns one rule per distinct TAINT rule ID present in the catalog, so
// SARIF reporting and rule-listing surface every ID this analyzer can emit. The
// descriptions state the class and the honest intraprocedural limit.
//
// A rule ID can be shared by sinks of several vulnerability classes: TAINT-005
// covers code_injection (CWE-94, CWE-95, CWE-134) and unsafe_deserialization
// (CWE-502), TAINT-003 covers xss and ssti. One rule serves every finding with
// its ID, so it describes every class and CWE the ID reports; each finding's
// own message and metadata carry its precise class and CWE. The IDs are not
// split per class: SARIF consumers key alerts on ruleId, so a split would move
// the identity of every existing TAINT-003 and TAINT-005 alert.
func (a *Analyzer) Rules() *rules.RuleSet {
	type ruleInfo struct {
		classes map[taint.VulnClass]bool
		cwes    map[string]bool
		// optIn holds only while every sink of the ID is opt-in; one default
		// sink makes the rule report by default.
		optIn bool
	}
	byID := map[string]*ruleInfo{}
	for _, lang := range a.cat.Languages() {
		for _, s := range a.cat.Sinks(lang) {
			info := byID[s.RuleID]
			if info == nil {
				info = &ruleInfo{classes: map[taint.VulnClass]bool{}, cwes: map[string]bool{}, optIn: true}
				byID[s.RuleID] = info
			}
			info.classes[s.VulnClass] = true
			info.cwes[s.CWE] = true
			info.optIn = info.optIn && s.OptIn
		}
	}

	rs := rules.NewRuleSet()
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		info := byID[id]
		classes := orderedClasses(info.classes)
		cwes := slices.SortedFunc(maps.Keys(info.cwes), compareCWE)
		classNames := make([]string, len(classes))
		severity := severityForClass(classes[0])
		for i, c := range classes {
			classNames[i] = string(c)
			if sev := severityForClass(c); findings.SeverityRank(sev) < findings.SeverityRank(severity) {
				severity = sev
			}
		}
		refs := make([]string, 0, len(cwes)+1)
		for _, cwe := range cwes {
			refs = append(refs, "https://cwe.mitre.org/data/definitions/"+cweNumber(cwe)+".html")
		}
		refs = append(refs, "https://owasp.org/www-community/Injection_Flaws")
		desc := fmt.Sprintf("Untrusted input reaches a %s sink (%s) without sanitization (intraprocedural taint flow)",
			strings.Join(classNames, " or "), strings.Join(cwes, ", "))
		rs.Add(&rules.Rule{
			ID:          id,
			Version:     "1.0",
			Description: desc,
			Severity:    severity,
			Confidence:  findings.ConfidenceMedium,
			Tags:        append([]string{"sast", "taint", "injection"}, classNames...),
			Remediation: "A value derived from untrusted input (a request parameter, environment variable, or similar) flows into a dangerous operation in the same function without passing through an appropriate sanitizer. Validate or neutralize the value for this sink's context (parameterized query, argument-vector exec, output escaping, path canonicalization + allow-list) before it reaches the sink. Note: this is intraprocedural analysis — it reasons within one function body only.",
			References:  refs,
			Metadata:    map[string]string{"cwe": strings.Join(cwes, ", "), "vuln_class": strings.Join(classNames, ", ")},
			OptIn:       info.optIn,
		})
	}
	return rs
}

// orderedClasses returns the classes in set in the taint model's fixed class
// order.
func orderedClasses(set map[taint.VulnClass]bool) []taint.VulnClass {
	var out []taint.VulnClass
	for _, c := range taint.AllVulnClasses() {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// compareCWE orders CWE identifiers by number, so CWE-94 precedes CWE-134; an
// identifier without a number sorts after those with one, by text.
func compareCWE(a, b string) int {
	na, errA := strconv.Atoi(cweNumber(a))
	nb, errB := strconv.Atoi(cweNumber(b))
	switch {
	case errA == nil && errB == nil && na != nb:
		return cmp.Compare(na, nb)
	case errA == nil && errB != nil:
		return -1
	case errA != nil && errB == nil:
		return 1
	}
	return strings.Compare(a, b)
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
	err := flowunits.Walk(ctx, artifacts, func(path string, units []taint.Unit) {
		a.ScanUnits(fs, path, units)
	})
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// ScanUnits emits a finding per un-sanitized flow in one file's units (from
// flowunits.Walk), as the engine deduplicates them, so a repeated sink call in
// one statement does not double-report.
func (a *Analyzer) ScanUnits(fs *findings.FindingSet, path string, units []taint.Unit) {
	// AnalyzeFile runs the whole file at once so it can join a source in one
	// function to a sink reached through a locally-defined helper (SAME-FILE
	// interprocedural flow via function summaries), in addition to the
	// intraprocedural flows Analyze finds. It de-duplicates a source→sink pair
	// reachable both ways, so a purely intraprocedural bug is still reported once.
	flows, suppressed := a.eng.AnalyzeFileWithSuppressions(units)
	for j := range flows {
		if flows[j].Sink.OptIn && !a.optIn[flows[j].Sink.RuleID] {
			continue
		}
		fs.Add(a.toFinding(&flows[j]))
	}
	a.recordSuppressions(path, suppressed)
}

// recordSuppressions files what the engine refused to report.
//
// The subject is the candidate the flow WOULD have been reported as, so a
// refutation and the finding it prevented land in the same ledger — which is
// what lets the stage accounting count them against the same family, and what
// would let a reader ask why a sink they expected to see is absent.
func (a *Analyzer) recordSuppressions(path string, ss []taint.Suppression) {
	for i := range ss {
		s := &ss[i]
		subject := reasoning.Candidate(s.RuleID, path, s.SinkLine, 1)
		// Scoped, not bare. A sanitizer refutation is a universal claim about
		// this value at this sink, and it is only as good as the analysis
		// behind it — which here is syntactic and per-file. Naming the blind
		// spots is what lets a reader decide whether they matter: a value that
		// arrives through an interface, a function value or reflection is a
		// value this engine did not follow, and the sanitizer it saw may not be
		// the one that ran.
		a.reasoning.RefuteWithin(subject, evidence.KindStatic, "nox-scan", "taint",
			s.Reason, reasoning.Scope{
				Analysis: "the " + s.Language + " taint engine, over this file",
				Limits:   "interface dispatch, function values, reflection, or a sanitizer applied in another file",
			})
	}
}

// toFinding maps a Flow to a findings.Finding using the sink's RuleID/CWE and a
// source→sink message, located at the sink call. The finding carries triage
// metadata: the vuln class, the source kind and variable, the sink call, and the
// source line.
func (a *Analyzer) toFinding(flow *taint.Flow) findings.Finding {
	sink := flow.Sink
	// A source used directly as the sink's argument (`eval "$@"`,
	// `os.system(request.args.get("c"))`) binds no variable; name the source
	// expression instead of an empty variable.
	origin := fmt.Sprintf("%s via %q", flow.Source.Kind, flow.SourceVar)
	if flow.SourceVar == "" {
		origin = fmt.Sprintf("%s from %q used directly", flow.Source.Kind, flow.Source.Call)
	}
	var msg string
	confidence := findings.ConfidenceMedium
	if sink.VulnClass == taint.VulnLogInjection {
		// Logging request data is everywhere; whether the log format or its
		// reader is affected by a line break is not established here.
		confidence = findings.ConfidenceLow
	}
	switch {
	case flow.Source.Kind == engine.SourceParameter:
		// No source in the file says the value is untrusted: what is shown is
		// a query assembled from the function's argument by string formatting.
		// Whether a caller passes request data in is not established here.
		msg = fmt.Sprintf(
			"SQL query built by string formatting from parameter %q of %s reaches sink %q — %s. "+
				"Untrusted input is not traced in this file: a caller that passes request data makes it injectable; bind it as a query parameter instead.",
			flow.SourceVar, flow.FuncName, sink.Call, sink.CWE,
		)
		confidence = findings.ConfidenceLow
	case len(flow.Via) > 0:
		// Cross-function flow: name the intermediate helper(s) so triage can follow
		// the path from the caller's source through the summarized helper(s) to the
		// sink.
		msg = fmt.Sprintf(
			"Untrusted input (%s) reaches %s sink %q through %s without sanitization — %s.",
			origin, sink.VulnClass, sink.Call, viaPath(flow.Via), sink.CWE,
		)
	default:
		msg = fmt.Sprintf(
			"Untrusted input (%s) reaches %s sink %q without sanitization — %s.",
			origin, sink.VulnClass, sink.Call, sink.CWE,
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
	// The calls the tainted value took, caller first, ending at the sink: the
	// evidence for an interprocedural flow reported where the sink is (ADR
	// 0007). Not call_path, which the call-graph stage writes as the path from
	// an entry point to the function -- reachability, a different claim. Kept
	// out of the message, which the fingerprint hashes, so a caller moving
	// does not move the finding's identity.
	if len(flow.Path) > 0 {
		meta["flow_path"] = callPath(flow)
		if len(flow.OtherPaths) > 0 {
			all := []string{meta["flow_path"]}
			for _, p := range flow.OtherPaths {
				all = append(all, renderPath(p, flow))
			}
			setFlowPaths(meta, all)
		}
	}
	if flow.SourceFile != "" {
		meta["source_file"] = flow.SourceFile
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
		Confidence: confidence,
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

// callPath renders a flow's calls and its sink, caller first, with each
// file as the scan names it: `handler (app.py:6) -> run (app.py:2)`.
// addFlowPaths records cross's call paths on the scan's finding i, which
// already reports the same sink: the cross-file caller is another injection
// point behind it, not a second finding. A finding with no call path (the sink
// reached in its own function) has no path list to extend.
func addFlowPaths(fs *findings.FindingSet, i int, cross findings.Finding) {
	have := fs.Findings()[i].Metadata
	if have["flow_path"] == "" || cross.Metadata["flow_path"] == "" {
		return
	}
	all := flowPaths(have)
	for _, p := range flowPaths(cross.Metadata) {
		if !slices.Contains(all, p) {
			all = append(all, p)
		}
	}
	if len(all) == len(flowPaths(have)) {
		return
	}
	fs.SetMetadata(i, "flow_paths", strings.Join(all, flowPathSep))
	fs.SetMetadata(i, "flow_path_count", strconv.Itoa(len(all)))
}

// flowPaths is every call path a finding's metadata records.
func flowPaths(meta map[string]string) []string {
	if all := meta["flow_paths"]; all != "" {
		return strings.Split(all, flowPathSep)
	}
	return []string{meta["flow_path"]}
}

func callPath(flow *taint.Flow) string {
	return renderPath(flow.Path, flow)
}

// flowPathSep separates the paths in flow_paths; " -> " joins the steps of one.
const flowPathSep = "; "

// setFlowPaths records every call path reaching a finding's sink: flow_paths
// lists them (the first is flow_path) and flow_path_count counts the callers,
// each a separate injection point behind the one finding.
func setFlowPaths(meta map[string]string, all []string) {
	meta["flow_paths"] = strings.Join(all, flowPathSep)
	meta["flow_path_count"] = strconv.Itoa(len(all))
}

// renderPath renders path, caller first, ending at flow's sink.
func renderPath(path []taint.CallStep, flow *taint.Flow) string {
	steps := make([]string, 0, len(path)+1)
	for _, s := range path {
		steps = append(steps, fmt.Sprintf("%s (%s:%d)", stepName(s.Func), s.File, s.Line))
	}
	steps = append(steps, fmt.Sprintf("%s (%s:%d)", stepName(flow.FuncName), flow.FilePath, flow.SinkLine))
	return strings.Join(steps, " -> ")
}

func stepName(fn string) string {
	if fn == "" {
		return "<module>"
	}
	return fn
}

// ScanCrossFile returns the findings for flows whose path crosses a file
// (ADR 0007): a source in one file reaching a sink in another through calls
// the call graph bound by the files' imports. files are the units the scan
// extracted; g is the source call graph built from them. Each finding is at
// the sink, with the call path as evidence. MergeCrossFile puts them beside
// the per-file findings.
func (a *Analyzer) ScanCrossFile(files []callgraph.FileUnits, g *callgraph.Graph) []findings.Finding {
	if g == nil || len(files) == 0 {
		return nil
	}
	in := make([]engine.CrossFile, 0, len(files))
	for _, f := range files {
		cf := engine.CrossFile{Path: f.Path, Units: f.Units}
		if callees := g.CrossFileCallees(f.Path); len(callees) > 0 {
			cf.Callees = make(map[string]engine.CalleeRef, len(callees))
			for call, c := range callees {
				cf.Callees[call] = engine.CalleeRef{File: c.File, Func: c.Func}
			}
		}
		in = append(in, cf)
	}
	flows := a.eng.AnalyzeCrossFile(in)
	out := make([]findings.Finding, 0, len(flows))
	for i := range flows {
		if flows[i].Sink.OptIn && !a.optIn[flows[i].Sink.RuleID] {
			continue
		}
		f := a.toFinding(&flows[i])
		f.Metadata["cross_file"] = "true"
		out = append(out, f)
	}
	return out
}

// MergeCrossFile adds cross-file findings to fs, the scan's findings, one per
// sink and rule: a sink a per-file flow already reports keeps that finding,
// and a parameter-SQL finding there (no source in its file, low confidence)
// is replaced by the flow that now has one (ADR 0007, rule 5). It returns how
// many were added, and supersede, which removes the parameter findings they
// replace; the caller runs it where a removal is recorded (the scan's
// withheld ledger), never silently.
func MergeCrossFile(fs *findings.FindingSet, cross []findings.Finding) (added int, supersede func()) {
	type at struct {
		rule, file string
		line       int
	}
	existing := map[at]int{}
	param := map[at]bool{}
	for i, f := range fs.Findings() {
		k := at{f.RuleID, f.Location.FilePath, f.Location.StartLine}
		if f.Metadata["source_kind"] == string(engine.SourceParameter) {
			param[k] = true
			continue
		}
		if _, ok := existing[k]; !ok {
			existing[k] = i
		}
	}
	var replaced []at
	for i := range cross {
		f := cross[i]
		k := at{f.RuleID, f.Location.FilePath, f.Location.StartLine}
		if j, ok := existing[k]; ok {
			addFlowPaths(fs, j, f)
			continue
		}
		existing[k] = len(fs.Findings())
		if param[k] {
			replaced = append(replaced, k)
		}
		fs.Add(f)
		added++
	}
	drop := map[at]bool{}
	for _, k := range replaced {
		drop[k] = true
	}
	return added, func() {
		if len(drop) == 0 {
			return
		}
		fs.RemoveWhere(func(f *findings.Finding) bool {
			return f.Metadata["source_kind"] == string(engine.SourceParameter) &&
				drop[at{f.RuleID, f.Location.FilePath, f.Location.StartLine}]
		})
	}
}
