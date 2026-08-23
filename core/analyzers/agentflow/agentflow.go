// Package agentflow is Nox's deterministic "agentic dataflow" analyzer: it flags
// the two prompt-injection-adjacent flows across an AI agent's data path that a
// single-line rule cannot see, because both require following a value from where
// it enters to where it is trusted.
//
//	AGENTFLOW-001 — untrusted input reaches an LLM prompt (goal hijack).
//	  External or tool-derived data (an HTTP request, a retrieved/RAG document, a
//	  tool/function result, a file, an environment variable) flows into a model
//	  prompt (messages=, prompt=, .chat.completions.create, .messages.create,
//	  .generate_content) without passing a sanitizer. The model can then be
//	  steered by attacker-controlled input. Maps to OWASP ASI01 / LLM01.
//	  (CWE-1427: improper neutralization of input used for LLM prompting.)
//
//	AGENTFLOW-002 — LLM output reaches a dangerous sink (excessive agency).
//	  A model's *response* (the result of an LLM call, and any member of it such
//	  as .choices[0].message.content or .text) flows into a shell/exec, SQL, eval,
//	  filesystem, or HTTP sink. The model is trusted to drive a dangerous action;
//	  a hijacked model then drives it with attacker intent. Maps to OWASP ASI02 /
//	  LLM06 (Excessive Agency, 2025 edition). (CWE-77: the model's output is an
//	  untrusted command.)
//
// WHY a dedicated analyzer rather than a taint rule: both flows treat the LLM
// boundary as a first-class node. AGENTFLOW-001 uses the existing untrusted
// sources but a NEW sink class (the LLM prompt). AGENTFLOW-002 is the genuinely
// new direction — the LLM CALL RESULT is itself the taint source, which the
// classic taint catalog does not model (it only treats the prompt as a sink).
// This analyzer reuses core/taint/engine's Unit extractor (statements with
// assigns/calls/reads, code-only via core/lexctx) and runs its own forward,
// straight-line, intraprocedural propagation over those Units.
//
// SCOPE AND LIMITS (honest, deterministic first version):
//   - Python and JS/TS only (whatever core/lexctx lexes as code).
//   - Intraprocedural and straight-line: source var → prompt arg, and LLM-call
//     result var → sink arg, within one function body, following simple
//     reassignment. No cross-function/cross-file flow, no control-flow graph, no
//     loops/branches merging, no alias or field sensitivity. A taint laundered
//     through an untracked dict/object is lost (may under-report); a taint that
//     only exists on one branch is treated as always present (may over-report).
//   - A recognized sanitizer/validator between source and prompt clears
//     AGENTFLOW-001; there is no sanitizer notion for AGENTFLOW-002 because
//     "trusting the model's output in a dangerous sink" has no safe-by-wrapping
//     form the way input escaping does.
package agentflow

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

// Rule IDs emitted by this analyzer. Kept as constants so the analyzer, its
// Rules() declaration, and tests never drift on the string.
const (
	ruleUntrustedToPrompt = "AGENTFLOW-001"
	ruleOutputToSink      = "AGENTFLOW-002"
)

// Analyzer runs the agentic-dataflow analysis over source artifacts. It holds
// the embedded taint catalog so it can reuse the catalog's untrusted-source and
// dangerous-sink knowledge; the LLM-prompt call set and the LLM-output accessor
// recognition are agentflow-specific and defined below.
type Analyzer struct {
	cat *taint.Catalog
}

// NewAnalyzer returns an agentflow analyzer backed by the embedded catalog.
func NewAnalyzer() *Analyzer {
	return &Analyzer{cat: taint.MustDefault()}
}

// Rules declares the two agentic-dataflow rules so rule listing, SARIF export,
// and the skip_analyzer action all know the IDs this analyzer can emit. The
// descriptions state the honest intraprocedural limit.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleUntrustedToPrompt,
		Version:     "1.0",
		Description: "Untrusted input reaches an LLM prompt without sanitization (agentic goal hijack, OWASP ASI01 / LLM01)",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"ai", "agentic", "prompt-injection", "owasp-asi01", "owasp-llm01"},
		Remediation: "A value derived from untrusted input (an HTTP request, a retrieved/RAG document, a tool/function result, a file, or an environment variable) flows into a model prompt in the same function without sanitization. An attacker who controls that input can steer the model (goal hijack). Keep untrusted content in the user role only, wrap it in explicit boundary markers, validate it against an allowlist, and never place it in the system role. Note: this is intraprocedural analysis — it reasons within one function body only.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1427.html",
			"https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		},
		Metadata: map[string]string{"cwe": "CWE-1427", "owasp_asi": "ASI01"},
	})
	rs.Add(&rules.Rule{
		ID:          ruleOutputToSink,
		Version:     "1.0",
		Description: "LLM output reaches a dangerous sink without validation (excessive agency, OWASP ASI02 / LLM06)",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"ai", "agentic", "excessive-agency", "owasp-asi02", "owasp-llm06"},
		Remediation: "The response from an LLM call flows into a dangerous operation (shell/exec, SQL, eval, filesystem, or outbound HTTP) in the same function. Treating model output as a trusted command is excessive agency: a prompt-injected model then drives that action with attacker intent. Do not pass model output to an interpreter, query, or command directly. Constrain the model to a fixed, validated action set (structured tool calls with schema validation and an allowlist), and add human confirmation for state-changing actions. Note: this is intraprocedural analysis — it reasons within one function body only.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/77.html",
			"https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		},
		Metadata: map[string]string{"cwe": "CWE-77", "owasp_asi": "ASI02"},
	})
	return rs
}

// ScanArtifacts runs the agentic-dataflow analysis over every Source artifact.
// It is deterministic: artifacts are processed in stable path order and each
// file's flows are sorted, so the FindingSet is reproducible.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

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
			continue // Python and JS/TS only
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		a.scanFile(fs, art.Path, lang, content)
	}
	return fs, nil
}

// scanFile extracts Units (reusing the taint engine's extractor) and runs both
// flow analyses over each Unit, deduplicating per (rule, line).
func (a *Analyzer) scanFile(fs *findings.FindingSet, path string, lang lexctx.Lang, content []byte) {
	units := engine.ExtractUnits(path, lang, content)
	seen := map[string]struct{}{}
	add := func(f *findings.Finding) {
		key := fmt.Sprintf("%s:%d", f.RuleID, f.Location.StartLine)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		fs.Add(*f)
	}
	for i := range units {
		flows := a.analyzeUnit(&units[i])
		for j := range flows {
			add(&flows[j])
		}
	}
}

// analyzeUnit runs one forward pass over a Unit's statements, tracking two taint
// colors at once so a single walk finds both flows:
//
//	"untrusted" — a value derived from a catalog untrusted source. Reaching an
//	  LLM-prompt call fires AGENTFLOW-001. Cleared by a catalog sanitizer.
//	"llmout"    — a value derived from an LLM call's result. Reaching a dangerous
//	  sink fires AGENTFLOW-002. Not cleared by input sanitizers (they do not make
//	  model output safe to execute).
//
// The two colors are independent maps so a variable can carry either or both.
// Straight-line, intraprocedural, following simple reassignment only.
func (a *Analyzer) analyzeUnit(unit *taint.Unit) []findings.Finding {
	lang := unit.Language
	// untrusted[var] = origin source that tainted it.
	untrusted := map[string]taint.Source{}
	untrustedLine := map[string]int{}
	// llmout[var] = line of the LLM call that produced it.
	llmout := map[string]int{}

	var out []findings.Finding

	for i := range unit.Stmts {
		st := &unit.Stmts[i]

		// 1) AGENTFLOW-001: an untrusted variable reaching an LLM-prompt call.
		for _, rawCall := range st.Calls {
			if !isPromptCall(rawCall) {
				continue
			}
			// If a sanitizer wraps the value at the call site, treat it as cleared.
			inlineSafe := a.stmtHasSanitizer(lang, st)
			// Role-awareness: reaching an LLM is necessary but not sufficient. The
			// same call's message array tells us WHERE the untrusted value lands. A
			// value confined to the user role behind a static system message is the
			// recommended pattern (suppressed); a value in the system/developer role
			// inverts the trust boundary (kept); an undetermined role is kept
			// conservatively. Determined for Python only (see detectPromptRoles).
			roles, staticSystem := promptRoleInfo(st, rawCall)
			for _, v := range promptArgVars(st, rawCall) {
				src, ok := untrusted[v]
				if !ok || inlineSafe {
					continue
				}
				role := taint.PromptRoleUnknown
				if r, known := roles[v]; known {
					role = r
				}
				if taint.SuppressPromptRole(role, staticSystem) {
					continue // untrusted content confined to the user role (safe pattern)
				}
				out = append(out, a.untrustedToPromptFinding(unit, st, rawCall, v, src, untrustedLine[v], role))
				break
			}
		}

		// 2) AGENTFLOW-002: an LLM-output variable reaching a dangerous sink.
		for _, rawCall := range st.Calls {
			sink, ok := a.resolveDangerousSink(lang, rawCall)
			if !ok {
				continue
			}
			for _, v := range sinkArgVars(st, rawCall) {
				line, ok := llmout[v]
				if !ok {
					continue
				}
				out = append(out, a.outputToSinkFinding(unit, st, rawCall, v, &sink, line))
				break
			}
		}

		// 3) Propagation into the assignee.
		if st.Assigns == "" {
			continue
		}

		// An LLM call assigned to a variable makes that variable LLM-output. This
		// takes precedence: `r = client.chat.completions.create(...)` colors r.
		if stmtCallsLLM(st) {
			llmout[st.Assigns] = st.Line
			// The prompt of that call may itself be untrusted, but the RESULT is
			// not untrusted input — clear any inherited untrusted color on the LHS.
			delete(untrusted, st.Assigns)
			delete(untrustedLine, st.Assigns)
			continue
		}

		// An untrusted source assigned to a variable colors it untrusted afresh.
		if src, ok := a.resolveUntrustedSource(lang, st); ok {
			untrusted[st.Assigns] = src
			untrustedLine[st.Assigns] = st.Line
			delete(llmout, st.Assigns)
			continue
		}

		// Otherwise propagate whichever color(s) the RHS reads carry. A sanitizer
		// call in this statement clears the untrusted color (input sanitizers do
		// not clear the llmout color).
		sanitized := a.stmtHasSanitizer(lang, st)
		var carriedUntrusted *taint.Source
		var carriedUntrustedLine int
		carriedLLMLine := -1
		for _, v := range st.Reads {
			if src, ok := untrusted[v]; ok && carriedUntrusted == nil {
				s := src
				carriedUntrusted = &s
				carriedUntrustedLine = untrustedLine[v]
			}
			if line, ok := llmout[v]; ok && carriedLLMLine == -1 {
				carriedLLMLine = line
			}
		}

		switch {
		case sanitized || carriedUntrusted == nil:
			delete(untrusted, st.Assigns)
			delete(untrustedLine, st.Assigns)
		default:
			untrusted[st.Assigns] = *carriedUntrusted
			untrustedLine[st.Assigns] = carriedUntrustedLine
		}
		if carriedLLMLine >= 0 {
			llmout[st.Assigns] = carriedLLMLine
		} else {
			delete(llmout, st.Assigns)
		}
	}

	sortFindings(out)
	return out
}

// resolveUntrustedSource returns the untrusted source introduced by st, matching
// its call chains and bare attribute chains against the catalog by dotted suffix.
// It deliberately EXCLUDES the LLM-prompt sinks that the catalog also lists as
// prompt_injection sinks (those are prompt destinations, not untrusted origins).
func (a *Analyzer) resolveUntrustedSource(lang string, st *taint.Statement) (taint.Source, bool) {
	for _, rawCall := range st.Calls {
		for _, key := range suffixKeys(rawCall) {
			if s, ok := a.cat.Source(lang, key); ok {
				return s, true
			}
		}
	}
	for _, chain := range st.Chains {
		for _, key := range suffixKeys(chain) {
			if s, ok := a.cat.Source(lang, key); ok {
				return s, true
			}
		}
	}
	return taint.Source{}, false
}

// resolveDangerousSink resolves a raw call to a catalog sink that is dangerous
// for LLM output — every sink class EXCEPT prompt_injection (the LLM prompt is
// not a "dangerous action driven by the model"; it is the model's own input).
func (a *Analyzer) resolveDangerousSink(lang, rawCall string) (taint.Sink, bool) {
	for _, key := range suffixKeys(rawCall) {
		if s, ok := a.cat.IsSink(lang, key); ok {
			if s.VulnClass == taint.VulnPromptInjection {
				return taint.Sink{}, false
			}
			return s, true
		}
	}
	return taint.Sink{}, false
}

// stmtHasSanitizer reports whether any call in st is a recognized catalog
// sanitizer/validator (for any vuln class). It is the AGENTFLOW-001 clearing
// signal: an untrusted value that passes through a validator before the prompt
// is treated as no longer attacker-controlled.
func (a *Analyzer) stmtHasSanitizer(lang string, st *taint.Statement) bool {
	for _, rawCall := range st.Calls {
		for _, key := range suffixKeys(rawCall) {
			for _, class := range allVulnClasses {
				if a.cat.IsSanitizer(lang, key, class) {
					return true
				}
			}
		}
	}
	return false
}

// untrustedToPromptFinding builds the AGENTFLOW-001 finding at the prompt call.
// role is the chat role the tainted value lands in ("system"/"developer"/"user"/
// "unknown"), recorded on the finding so the role-based verdict is auditable. A
// system/developer role is the trust-inverting injection; an unknown role is a
// conservatively-kept ambiguous case.
func (a *Analyzer) untrustedToPromptFinding(unit *taint.Unit, st *taint.Statement, call, srcVar string, src taint.Source, srcLine int, role string) findings.Finding {
	msg := fmt.Sprintf(
		"Untrusted input (%s via %q) reaches LLM prompt call %q in the %s role without sanitization — the model can be goal-hijacked (ASI01).",
		src.Kind, srcVar, call, role,
	)
	return findings.Finding{
		RuleID:     ruleUntrustedToPrompt,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: unit.FilePath, StartLine: st.Line, EndLine: st.Line},
		Message:    msg,
		Metadata: map[string]string{
			"cwe":         "CWE-1427",
			"owasp_asi":   "ASI01",
			"flow":        "untrusted_input->llm_prompt",
			"prompt_call": call,
			"source_kind": string(src.Kind),
			"source_call": src.Call,
			"source_var":  srcVar,
			"source_line": fmt.Sprintf("%d", srcLine),
			"sink_role":   role,
			"function":    unit.FuncName,
		},
	}
}

// promptRoleInfo returns the per-variable chat-role map and the static-system-message
// flag for a specific prompt call in st, resolved from the extractor's per-call
// argument evidence (with dotted-suffix fallback so a framework/aliased prefix
// resolves). Both are empty/false when the call is not chat-message-shaped or the
// language is not Python, in which case every reaching value keeps its conservative
// (role-blind) verdict.
func promptRoleInfo(st *taint.Statement, rawCall string) (map[string]string, bool) {
	if st.SinkArgs == nil {
		return nil, false
	}
	if info, ok := st.SinkArgs[rawCall]; ok {
		return info.PromptRoles, info.PromptHasStaticSystem
	}
	for _, key := range suffixKeys(rawCall) {
		if info, ok := st.SinkArgs[key]; ok {
			return info.PromptRoles, info.PromptHasStaticSystem
		}
	}
	return nil, false
}

// outputToSinkFinding builds the AGENTFLOW-002 finding at the dangerous sink.
func (a *Analyzer) outputToSinkFinding(unit *taint.Unit, st *taint.Statement, call, outVar string, sink *taint.Sink, llmLine int) findings.Finding {
	msg := fmt.Sprintf(
		"LLM output (via %q) reaches %s sink %q without validation — excessive agency lets a hijacked model drive a dangerous action (ASI02, %s).",
		outVar, sink.VulnClass, call, sink.CWE,
	)
	return findings.Finding{
		RuleID:     ruleOutputToSink,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: unit.FilePath, StartLine: st.Line, EndLine: st.Line},
		Message:    msg,
		Metadata: map[string]string{
			"cwe":        "CWE-77",
			"sink_cwe":   sink.CWE,
			"owasp_asi":  "ASI02",
			"flow":       "llm_output->dangerous_sink",
			"sink":       sink.Call,
			"vuln_class": string(sink.VulnClass),
			"llm_var":    outVar,
			"llm_line":   fmt.Sprintf("%d", llmLine),
			"function":   unit.FuncName,
		},
	}
}

// promptArgVars returns the variables that reach an LLM-prompt call. Prompt
// content can arrive positionally, as a keyword (messages=, prompt=,
// contents=), or nested in a message list literal; the extractor's per-call
// arg vars (which include the head of any dotted chain) capture all of these,
// so we prefer them and fall back to the whole statement's reads.
func promptArgVars(st *taint.Statement, rawCall string) []string {
	return sinkArgVars(st, rawCall)
}

// sinkArgVars returns the variables passed as arguments to a specific call,
// preferring the extractor's precise per-call arg vars and falling back to the
// statement's whole Reads set when none were captured.
func sinkArgVars(st *taint.Statement, rawCall string) []string {
	if st.SinkArgs != nil {
		if info, ok := st.SinkArgs[rawCall]; ok && len(info.TaintedArgVars) > 0 {
			return info.TaintedArgVars
		}
		for _, key := range suffixKeys(rawCall) {
			if info, ok := st.SinkArgs[key]; ok && len(info.TaintedArgVars) > 0 {
				return info.TaintedArgVars
			}
		}
	}
	return st.Reads
}

// stmtCallsLLM reports whether st invokes an LLM call whose result is a model
// response worth tracking as output taint.
func stmtCallsLLM(st *taint.Statement) bool {
	for _, rawCall := range st.Calls {
		if isPromptCall(rawCall) {
			return true
		}
	}
	return false
}

// llmPromptCalls is the set of model-invocation call suffixes recognized as the
// LLM boundary, shared by both flows: AGENTFLOW-001 treats them as the prompt
// SINK, and AGENTFLOW-002 treats their RESULT as the output SOURCE. Matched by
// dotted-suffix so framework/aliased prefixes resolve (openai.chat.completions.
// create → chat.completions.create). Kept as an explicit set — not derived from
// the taint catalog's prompt_injection sinks — so embedding calls (which do not
// produce steerable text output) are excluded from the AGENTFLOW-002 source set.
var llmPromptCalls = map[string]struct{}{
	"chat.completions.create": {},
	"completions.create":      {},
	"ChatCompletion.create":   {},
	"messages.create":         {},
	"messages.stream":         {},
	"generate_content":        {},
	"generateContent":         {},
	"litellm.completion":      {},
	"invoke_model":            {},
	"converse":                {},
}

// isPromptCall reports whether a raw call chain is an LLM model invocation.
func isPromptCall(rawCall string) bool {
	for _, key := range suffixKeys(rawCall) {
		if _, ok := llmPromptCalls[key]; ok {
			return true
		}
	}
	return false
}

// suffixKeys returns the dotted suffixes of a call chain, longest first, so a
// prefixed/aliased chain resolves to the catalog's canonical suffix. Mirrors the
// engine's own suffix matching (kept local to avoid exporting engine internals).
func suffixKeys(chain string) []string {
	parts := strings.Split(chain, ".")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// allVulnClasses is the fixed class set consulted when checking whether a call
// is any sanitizer. Ordered deterministically.
var allVulnClasses = []taint.VulnClass{
	taint.VulnCommandInjection,
	taint.VulnSQLInjection,
	taint.VulnCodeInjection,
	taint.VulnXSS,
	taint.VulnSSTI,
	taint.VulnPathTraversal,
	taint.VulnSSRF,
	taint.VulnUnsafeDeserialization,
	taint.VulnPromptInjection,
}

// sortFindings orders findings deterministically by line, then rule ID, so
// repeated runs over one Unit produce identical output.
func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Location.StartLine != fs[j].Location.StartLine {
			return fs[i].Location.StartLine < fs[j].Location.StartLine
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
