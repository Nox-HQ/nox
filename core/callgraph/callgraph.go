// Package callgraph builds a syntactic call graph over a Go module and answers
// two questions nothing in nox could answer before: is there a call path to
// this code, and does one start at an entry point.
//
// # What it can and cannot establish, and why the asymmetry is the design
//
// Finding a path is EXISTENTIAL. One witness settles it, and a witness this
// package produces is a real chain of call expressions a reader can follow. An
// analysis that missed other paths can still have found this one, so a positive
// answer is sound however incomplete the search was.
//
// Proving no path exists is UNIVERSAL, and a syntactic graph cannot do it. Go
// dispatches through interfaces, function values, struct fields holding
// funcs, generics, embedded types, reflection and generated code. Every one of
// those is a call this package cannot resolve from syntax alone, and each is a
// place a path could hide.
//
// So this package NEVER refutes. Every Scope it builds carries at least one
// limitation, which makes reach.Refute decline to construct a negative from it
// and hand back Undetermined instead. That is not a gap to close later — a
// scanner that reports "no call path" from a graph that cannot see interface
// dispatch is reporting its own blind spot as an all-clear, which is the single
// failure the whole capability model exists to prevent.
//
// The useful half is still large. Before this, call_graph and entry_point were
// provided by nothing, so every finding carried "nothing on this installation
// can answer it". Now a Go finding can carry a path from main to the line, with
// the calls named.
package callgraph

import (
	"sort"

	"github.com/nox-hq/nox/core/reach"
)

// Func is one function or method in the graph.
type Func struct {
	// Key is the unique identifier: "<dir>.<name>" for a function,
	// "<dir>.(<recv>).<name>" for a method. The directory rather than the
	// package name, because two packages in one module can share a name.
	Key string
	// Name is the declared identifier, for rendering.
	Name string
	// File and Line locate the declaration.
	File string
	Line int
	// Calls are the keys this function calls, resolved where possible.
	Calls []string
	// Kind says whether execution can begin here, and on whose authority.
	Kind EntryKind
	// EntryReason says why, so an operator can disagree with the set.
	EntryReason string
}

// EntryKind distinguishes where execution can actually begin from where it
// could in principle.
//
// The distinction is load-bearing and was missing from the first version of
// this package, which counted every exported function as an entry point. On
// nox's own tree that made 5,088 of 7,652 functions entry points, so every
// query returned a path of length one — "this exported function is reachable
// because it is exported" — which is true, trivial, and reads like a much
// stronger claim than it is.
//
// An exported function in a library IS reachable by somebody. What nothing here
// establishes is that anybody actually calls it, which is precisely the
// difference between reach.CallPathExists and reach.AttackerEntryPathExists.
type EntryKind int

const (
	// NotAnEntry — nothing begins execution here.
	NotAnEntry EntryKind = iota
	// EntryExported — an external caller COULD reach it. Evidence that a path
	// is possible, never that one exists.
	EntryExported
	// EntryTest — the test runner calls it. Real execution, but of the test
	// suite rather than of the program an attacker meets.
	EntryTest
	// EntryConcrete — main or init. Execution genuinely begins here when the
	// program runs, with no caller outside the module required.
	EntryConcrete
)

// String renders the kind for a scope description.
func (k EntryKind) String() string {
	switch k {
	case EntryConcrete:
		return "concrete"
	case EntryTest:
		return "test"
	case EntryExported:
		return "exported"
	default:
		return "none"
	}
}

// Graph is a call graph over one module.
//
// The zero Graph is usable and answers nothing, which is what a caller gets
// when the module could not be read — an empty graph reports no paths and its
// scope says why, rather than the build failing.
type Graph struct {
	funcs map[string]*Func
	// callers is the reverse index, built once, so PathTo can search backwards
	// from the target instead of forwards from every entry.
	callers map[string][]string
	limits  map[reach.Limitation]bool
	// unresolved counts calls that could not be bound to a declaration. It is
	// the honest measure of how much of the program this graph does not model.
	unresolved int
	resolved   int
	// external counts calls out of the module — the standard library, a
	// dependency. Counted apart from unresolved because they are a different
	// kind of not-knowing: the callee is real and its source is simply not
	// here, which does not make a path inside this module invisible.
	external int
	// intoPackage maps an import path outside this module to the functions in
	// it that call into that package. The edge cannot be built — the callee's
	// source is elsewhere — but the caller is here, and "does anything in this
	// build reach for the affected package, and can execution get there" is
	// exactly what a dependency advisory asks.
	intoPackage map[string][]string
	root        string
	module      string
}

// Len returns the number of functions in the graph.
func (g *Graph) Len() int {
	if g == nil {
		return 0
	}
	return len(g.funcs)
}

// Unresolved returns how many call sites could not be bound to a declaration,
// and how many could. The ratio is what a reader should judge a negative
// result by — and the reason this package does not produce negatives.
func (g *Graph) Unresolved() (unresolved, resolved, external int) {
	if g == nil {
		return 0, 0, 0
	}
	return g.unresolved, g.resolved, g.external
}

// EntryPoints returns the functions execution can begin at, at kind or
// stronger, sorted.
//
// Passing EntryConcrete asks the question that matters for exploitability —
// where does this program actually start — and on a library the answer is often
// "nowhere", which is the honest result rather than an empty one.
func (g *Graph) EntryPoints(atLeast EntryKind) []string {
	if g == nil {
		return nil
	}
	var out []string
	for k, f := range g.funcs {
		if f.Kind >= atLeast && f.Kind != NotAnEntry {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Func returns the declaration for a key.
func (g *Graph) Func(key string) (*Func, bool) {
	if g == nil {
		return nil, false
	}
	f, ok := g.funcs[key]
	return f, ok
}

// Scope describes what this analysis covered and what defeated it.
//
// It always carries limitations. See the package doc: a syntactic graph cannot
// see every call Go can make, so no scope built here may support a universal
// claim, and reach.Refute declines to build one from it.
func (g *Graph) Scope() reach.Scope {
	s := reach.Scope{
		Analysis: "go/ast call graph",
		BuildID:  "syntactic, single module",
	}
	if g != nil {
		// The concrete set. Listing every exported function would describe a
		// search far broader than the one that answers "can this run".
		s.EntryPoints = g.EntryPoints(EntryConcrete)
		for l := range g.limits {
			s.Limitations = append(s.Limitations, l)
		}
	}
	// The floor. Even a module where nothing dynamic was OBSERVED is a module
	// this analysis read syntactically, and a call it did not see is exactly
	// the call it cannot report not seeing.
	if len(s.Limitations) == 0 {
		s.Limitations = append(s.Limitations, reach.UnresolvedDispatch)
	}
	sort.Slice(s.Limitations, func(i, j int) bool { return s.Limitations[i] < s.Limitations[j] })
	return s
}

// PathToFunc returns a call path reaching target, and the strongest kind of
// entry point that path starts at.
//
// The second return is not a detail. reach.AttackerEntryPathExists is strictly
// stronger than reach.CallPathExists, and a path from main is different
// evidence from a path from an exported function nothing in this module calls.
// Returning a path without saying which would let a caller promote one to the
// other by accident, which is the promotion the whole ladder exists to prevent.
func (g *Graph) PathToFunc(target string) (path []string, reached EntryKind) {
	if g == nil {
		return nil, NotAnEntry
	}
	if _, ok := g.funcs[target]; !ok {
		return nil, NotAnEntry
	}
	// Breadth-first backwards over callers, so the first path found is a
	// shortest one — the most readable witness, and deterministic because the
	// caller lists are sorted at build time.
	seen := map[string]bool{target: true}
	queue := []*searchNode{{key: target}}
	var best *searchNode
	bestKind := NotAnEntry

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if f, ok := g.funcs[n.key]; ok && f.Kind > bestKind {
			best, bestKind = n, f.Kind
			// Concrete is the strongest answer available, so stop. Anything
			// weaker keeps searching, because a longer path from main beats a
			// short one from an exported function nothing calls.
			if bestKind == EntryConcrete {
				break
			}
		}
		for _, c := range g.callers[n.key] {
			if seen[c] {
				continue
			}
			seen[c] = true
			queue = append(queue, &searchNode{key: c, prev: n})
		}
	}
	if best != nil {
		return chain(best), bestKind
	}
	return nil, NotAnEntry
}

// searchNode is one step of the backwards walk, linked to the step it came
// from so a completed search can be read back as a path.
type searchNode struct {
	key  string
	prev *searchNode
}

// chain walks a search node back to its origin and returns the path in CALL
// order — caller first, target last, which is how a person reads a stack. The
// walk itself runs the other way, and returning it unreversed would hand the
// reader a path that appears to start at the vulnerability.
func chain(n *searchNode) []string {
	var out []string
	for cur := n; cur != nil; cur = cur.prev {
		out = append(out, cur.key)
	}
	return out
}

// FuncAt returns the function whose declaration encloses file:line.
//
// It answers the question a finding actually poses. A finding names a line, the
// graph names functions, and without this join every reachability question
// about a scan result would have to be asked by hand.
//
// "Encloses" is approximated by the nearest declaration at or above the line in
// the same file, because the graph records declaration positions rather than
// bodies. That is right for the overwhelming case and wrong for a line after
// the last function in a file — a package-level var, an import — which is why
// it returns false rather than guessing when nothing precedes the line.
func (g *Graph) FuncAt(file string, line int) (string, bool) {
	if g == nil || file == "" || line <= 0 {
		return "", false
	}
	best, bestLine := "", 0
	for key, f := range g.funcs {
		if f.File != file || f.Line > line {
			continue
		}
		if f.Line > bestLine || (f.Line == bestLine && key < best) {
			best, bestLine = key, f.Line
		}
	}
	return best, best != ""
}

// Files returns the source files the graph parsed, sorted. A caller uses it to
// tell "this file was analysed and held nothing" from "this file was not
// analysed" — the same distinction the capability model draws everywhere else.
func (g *Graph) Files() []string {
	if g == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, f := range g.funcs {
		seen[f.File] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// CallersOfPackage returns the functions in this module that call into the
// given import path, sorted.
//
// It is the join between a dependency advisory and this module's own code. An
// advisory names an import path; `go list -deps` says whether the build links
// it; this says which of your functions actually reaches for it — and
// PathToFunc then says whether execution can get to those functions.
//
// Empty means no call was resolved to that path, which is NOT evidence that
// none exists. A call through an interface, a function value or reflection is
// invisible here, as everywhere in this package.
func (g *Graph) CallersOfPackage(importPath string) []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.intoPackage[importPath]...)
}
