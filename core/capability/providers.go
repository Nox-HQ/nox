package capability

// This file declares what nox's own built-in analyses can establish.
//
// It is a hand-written list, and that is a liability worth naming: a new
// analyzer that forgets to appear here is invisible to the matrix, and its
// capability reads as Unsupported when it is in fact provided. The alternative
// — deriving the list by reflection or by scanning imports — would be worse in
// the direction that matters, because it would report capabilities as present
// on the strength of a package existing rather than of it running.
//
// TestBuiltinsCoverWhatTheyClaim pins the entries that can be checked against
// the code they describe.

// builtin is a Provider defined by a static list.
type builtin struct {
	name     string
	provides []AnalysisCapability
}

// Name identifies the built-in implementation for reporting.
func (b builtin) Name() string { return b.name }

// Provides lists the capabilities this built-in can establish.
func (b builtin) Provides() []AnalysisCapability { return b.provides }

// Builtins returns the capabilities nox provides without any plugin installed.
//
// The list is deliberately short, and its shortness is the honest reading of
// what a pattern scanner is. nox lexes, it resolves constants where a language
// engine exists, and it tracks taint. It does not build a call graph, does not
// know entry points, and cannot establish reachability or attacker
// reachability — those come from plugins, or from nowhere.
//
// Stating that plainly is the point. An operator running nox with no plugins
// should be able to see that reachability was never on the table, rather than
// inferring safety from its silence.
func Builtins() []Provider {
	return []Provider{
		// core/lexctx classifies comment and string regions in 22 languages
		// and is what the secrets refiners consult before dropping a match.
		builtin{"core/lexctx", []AnalysisCapability{LexicalContext}},
		// core/taint resolves source-to-sink dataflow, and its extractors
		// resolve symbols within a file to do it.
		builtin{"core/taint", []AnalysisCapability{Taint, SymbolResolution}},
		// core/analyzers/deps answers reachability for Go only, via
		// `go list -deps`, and answers it with (reachable, determined) so an
		// undetermined result never reads as unreachable.
		builtin{"core/analyzers/deps", []AnalysisCapability{Reachability}},
		// core/attack constructs and executes exploit hypotheses. It is listed
		// because it exists, NOT because a scan uses it: `nox scan` never
		// executes anything, so DynamicVerification is NotEvaluated on every
		// scan finding rather than absent from the installation.
		builtin{"core/attack", []AnalysisCapability{DynamicVerification, AttackerReachability}},
	}
}

// DefaultRegistry returns a registry holding nox's built-in providers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, p := range Builtins() {
		r.Register(p)
	}
	return r
}
