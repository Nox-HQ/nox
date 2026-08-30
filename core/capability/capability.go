// Package capability names what an analysis can establish, records whether it
// actually ran, and keeps "we did not look" from reading like "there is
// nothing there".
//
// nox degrades gracefully in many places by design — an OSV outage should not
// fail a build, a plugin that will not start should not stop the scan. The
// degrade package already makes those failures visible. What it cannot express
// is the positive half: which analyses were SUPPOSED to run over a given
// subject, which of them did, and what they concluded.
//
// Without that half, the most dangerous state in a security scanner is
// invisible. A finding that no reachability analysis ever examined and a
// finding that reachability examined and cleared produce the same output —
// silence — and silence is read as safety. That is the single failure this
// package exists to prevent, and it becomes acute the moment refutation can
// change what is reported: a refiner that never ran must never be mistaken for
// one that ran and found nothing.
//
// # Why not "Capability"
//
// core/analyzers/ai already uses Capability for what an AI agent's TOOLS can
// do — file_read, shell_exec, http_request — and renders it with
// `nox agent-graph`. That is a different concept in the same neighbourhood,
// about the software under scan rather than about nox. Naming this one
// AnalysisCapability keeps a reader from having to guess which is meant, and
// keeps `nox analysis-capabilities` from reading like a synonym for a command
// that already exists.
package capability

import "sort"

// AnalysisCapability names a question an analysis can answer.
//
// The set is closed and deliberately small. It describes what nox can
// establish, not how — an implementation may be a core analyzer, a plugin, or
// a language-specific engine, and several may provide the same capability for
// different languages. The concept belongs to nox; the implementation does not
// have to.
type AnalysisCapability string

// The capabilities nox reasons about, roughly in order of cost.
const (
	// LexicalContext distinguishes code from comments and string literals.
	// The cheapest refutation there is, and the one most likely to be wrong in
	// a language nobody has written a lexer for.
	LexicalContext AnalysisCapability = "lexical_context"
	// ConstantEvaluation resolves whether an expression is a compile-time
	// constant. It is what separates a call that could take attacker input from
	// one that demonstrably cannot.
	ConstantEvaluation AnalysisCapability = "constant_evaluation"
	// SymbolResolution binds a name to the thing it refers to. Everything below
	// this line depends on it, which is why its absence is worth reporting
	// rather than inferring from the silence of the analyses above it.
	SymbolResolution AnalysisCapability = "symbol_resolution"
	// Taint tracks untrusted values from sources to sinks.
	Taint AnalysisCapability = "taint"
	// CallGraph relates callers to callees across function boundaries.
	CallGraph AnalysisCapability = "call_graph"
	// EntryPoint identifies where externally-triggered execution begins.
	EntryPoint AnalysisCapability = "entry_point"
	// Reachability establishes whether a symbol or path can be executed at all.
	Reachability AnalysisCapability = "reachability"
	// AttackerReachability establishes whether an attacker can cause it to be
	// executed. Strictly stronger than Reachability, and the two are separate
	// because conflating them is how "the code runs" becomes "the code is
	// exploitable".
	AttackerReachability AnalysisCapability = "attacker_reachability"
	// DynamicVerification observes a security invariant actually being
	// violated. The only capability that can support a CONFIRMED verdict, and
	// nox never exercises it during a scan.
	DynamicVerification AnalysisCapability = "dynamic_verification"
)

// all is the closed set, in declaration order — cheapest first, which is also
// the order a progressive pipeline should attempt them in.
var all = []AnalysisCapability{
	LexicalContext, ConstantEvaluation, SymbolResolution, Taint,
	CallGraph, EntryPoint, Reachability, AttackerReachability, DynamicVerification,
}

var valid = func() map[AnalysisCapability]bool {
	m := make(map[AnalysisCapability]bool, len(all))
	for _, c := range all {
		m[c] = true
	}
	return m
}()

// All returns every defined capability, cheapest first.
func All() []AnalysisCapability {
	out := make([]AnalysisCapability, len(all))
	copy(out, all)
	return out
}

// Valid reports whether c is a defined capability. An unrecognised capability
// is never treated as provided: a producer claiming one nox does not know
// about has told nox nothing, and reading it as coverage would be worse than
// reading it as absence.
func (c AnalysisCapability) Valid() bool { return valid[c] }

// State is what happened when a capability met a subject.
//
// Six states, and the distinctions between them are the entire point. Five of
// them would collapse into "no finding" without this type, and a security tool
// that cannot tell them apart is one that reports its own blind spots as
// all-clears.
type State string

// Evaluation states.
const (
	// NotEvaluated — the capability exists and nothing asked it. The default,
	// and the one that must never be read as a result.
	NotEvaluated State = "not_evaluated"
	// Unsupported — the capability cannot apply here at all: no lexer for this
	// language, no call graph for this ecosystem. Honest and permanent, as
	// opposed to a failure.
	Unsupported State = "unsupported"
	// TimedOut — it started and was cut short. Distinct from Unknown because
	// the answer was reachable and nox declined to pay for it, which is a
	// budget decision an operator may want to revisit.
	TimedOut State = "timed_out"
	// Unknown — it ran to completion and could not decide. The most honest
	// answer an analysis can give, and the one most easily mistaken for a
	// clearance.
	Unknown State = "unknown"
	// Negative — it ran and established the condition does NOT hold. This is
	// the only state that may support suppressing a finding.
	Negative State = "negative"
	// Positive — it ran and established the condition holds.
	Positive State = "positive"
)

var validStates = map[State]bool{
	NotEvaluated: true, Unsupported: true, TimedOut: true,
	Unknown: true, Negative: true, Positive: true,
}

// Valid reports whether s is a defined state.
func (s State) Valid() bool { return validStates[s] }

// Conclusive reports whether the capability actually reached an answer.
//
// Only Positive and Negative are conclusive. Everything else — not evaluated,
// unsupported, timed out, ran-and-could-not-tell — is an absence of knowledge,
// and this method exists so no caller has to enumerate that list correctly.
// Getting the enumeration wrong in one place is how a blind spot becomes a
// clearance, and an unrecognised state is not conclusive either.
func (s State) Conclusive() bool { return s == Positive || s == Negative }

// SuppressesFinding reports whether this state may justify not reporting
// something.
//
// Only Negative does. That is Gate B written as a method: deterministic
// unreachability may suppress a finding; unknown, unsupported, timed-out and
// never-evaluated may not, however much they resemble each other in the
// output.
func (s State) SuppressesFinding() bool { return s == Negative }

// Describe renders a state for a person, in wording that never overstates it.
func (s State) Describe() string {
	switch s {
	case NotEvaluated:
		return "not evaluated — nothing asked this question"
	case Unsupported:
		return "unsupported — this analysis cannot apply here"
	case TimedOut:
		return "timed out — the analysis was cut short, not completed"
	case Unknown:
		return "evaluated, and could not determine an answer"
	case Negative:
		return "evaluated — the condition does not hold"
	case Positive:
		return "evaluated — the condition holds"
	default:
		return "unknown evaluation state"
	}
}

// Provider is an implementation that declares which capabilities it offers.
// A core analyzer, a plugin, and a language engine all satisfy it the same way.
type Provider interface {
	// Name identifies the implementation for reporting: "nox/taint-analysis",
	// "core/lexctx".
	Name() string
	// Provides lists the capabilities this implementation can answer.
	Provides() []AnalysisCapability
}

// Registry records which implementations provide which capabilities.
//
// It answers the question that makes NotEvaluated meaningful: a capability
// nobody provides is honestly Unsupported, while a capability something
// provides and that nevertheless said nothing is NotEvaluated — a gap rather
// than a limit. Without the registry those two are indistinguishable, and the
// difference is exactly what an operator needs to act on.
//
// The zero Registry is usable and provides nothing.
type Registry struct {
	providers map[AnalysisCapability][]string
	names     map[string][]AnalysisCapability
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[AnalysisCapability][]string),
		names:     make(map[string][]AnalysisCapability),
	}
}

// Register records what p provides. Capabilities nox does not recognise are
// ignored rather than stored: a producer claiming an unknown capability has
// told nox nothing, and recording it would make the matrix look more covered
// than it is.
func (r *Registry) Register(p Provider) {
	if r == nil || p == nil {
		return
	}
	if r.providers == nil {
		r.providers = make(map[AnalysisCapability][]string)
		r.names = make(map[string][]AnalysisCapability)
	}
	for _, c := range p.Provides() {
		if !c.Valid() {
			continue
		}
		r.providers[c] = append(r.providers[c], p.Name())
		r.names[p.Name()] = append(r.names[p.Name()], c)
	}
}

// ProvidedBy returns the implementations offering c, sorted for determinism.
func (r *Registry) ProvidedBy(c AnalysisCapability) []string {
	if r == nil {
		return nil
	}
	out := append([]string(nil), r.providers[c]...)
	sort.Strings(out)
	return out
}

// Provided reports whether anything at all offers c. A capability nothing
// provides is Unsupported rather than NotEvaluated — a limit nox can state
// plainly, rather than a gap that looks like one.
func (r *Registry) Provided(c AnalysisCapability) bool {
	return len(r.ProvidedBy(c)) > 0
}

// Missing returns the defined capabilities nothing provides, cheapest first.
// It is the honest answer to "what can this installation not tell you?".
func (r *Registry) Missing() []AnalysisCapability {
	var out []AnalysisCapability
	for _, c := range All() {
		if !r.Provided(c) {
			out = append(out, c)
		}
	}
	return out
}

// Providers returns every registered implementation name, sorted.
func (r *Registry) Providers() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.names))
	for name := range r.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
