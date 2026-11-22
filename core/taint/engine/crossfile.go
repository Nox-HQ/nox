package engine

import (
	"sort"

	"github.com/nox-hq/nox/core/taint"
)

// Cross-file taint through function summaries (ADR 0007).
//
// The same-file pass (interproc.go) summarizes every function and resolves a
// call to a function of the same file by name. This pass adds the calls the
// call graph (core/callgraph) bound to a function in ANOTHER file, by the
// caller file's imports: each such call is given the callee's summary, the
// summaries are refined to a fixpoint across files, and every unit making
// such a call is analysed again. It reports only flows whose path crosses a
// file; everything else is the per-file pass's, unchanged.

// CrossFile is one file's units and the calls in it the call graph bound to
// a function in another file, keyed by the call as the units record it.
type CrossFile struct {
	Path    string
	Units   []taint.Unit
	Callees map[string]CalleeRef
}

// CalleeRef names a function by its file and its unit's FuncName.
type CalleeRef struct {
	File, Func string
}

// maxCrossFileRounds bounds the fixpoint across files. Each round recomputes
// the summaries of every file with a resolved cross-file call; the lattice is
// monotone, so stopping at the bound leaves summaries incomplete, never wrong.
const maxCrossFileRounds = 4

// externalKey is the summary-map key of a call bound to another file. The NUL
// keeps it from colliding with any function name.
func externalKey(rawCall string) string { return "\x00ext:" + rawCall }

// AnalyzeCrossFile returns the flows whose path crosses a file, deterministic
// and one per sink and rule. files may be in any order.
func (e *StructuralEngine) AnalyzeCrossFile(files []CrossFile) []taint.Flow {
	files = append([]CrossFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	byPath := make(map[string]int, len(files))
	for i := range files {
		if len(files[i].Units) > 0 {
			byPath[files[i].Path] = i
		}
	}
	lang := func(i int) string { return files[i].Units[0].Language }
	local := make([]map[string]*funcSummary, len(files))
	for i := range files {
		if len(files[i].Units) > 0 {
			local[i] = e.computeSummaries(lang(i), e.withPropertySanitizers(files[i].Units))
		}
	}
	// external builds file i's view of its cross-file callees from the
	// current summaries; names records which summaries are external, so a
	// flow through one is recognised as crossing a file.
	names := map[string]bool{}
	external := func(i int) map[string]*funcSummary {
		var out map[string]*funcSummary
		calls := make([]string, 0, len(files[i].Callees))
		for c := range files[i].Callees {
			calls = append(calls, c)
		}
		sort.Strings(calls)
		for _, call := range calls {
			ref := files[i].Callees[call]
			j, ok := byPath[ref.File]
			if !ok || j == i || lang(j) != lang(i) {
				continue
			}
			sum := local[j][ref.Func]
			if sum == nil || !hasEffect(sum) {
				continue
			}
			cp := *sum
			cp.name = ref.File + ":" + ref.Func
			names[cp.name] = true
			if out == nil {
				out = map[string]*funcSummary{}
			}
			out[externalKey(call)] = &cp
		}
		return out
	}
	for round := 0; round < maxCrossFileRounds; round++ {
		changed := false
		for i := range files {
			if len(files[i].Units) == 0 || len(files[i].Callees) == 0 {
				continue
			}
			ext := external(i)
			if ext == nil {
				continue
			}
			next := e.computeSummariesWith(lang(i), e.withPropertySanitizers(files[i].Units), ext)
			for name, s := range next {
				if !summaryEqual(local[i][name], s) {
					changed = true
				}
			}
			local[i] = next
		}
		if !changed {
			break
		}
	}

	var flows []taint.Flow
	for i := range files {
		if len(files[i].Units) == 0 || len(files[i].Callees) == 0 {
			continue
		}
		ext := external(i)
		if ext == nil {
			continue
		}
		summaries := make(map[string]*funcSummary, len(local[i])+len(ext))
		for k, v := range local[i] {
			summaries[k] = v
		}
		for k, v := range ext {
			summaries[k] = v
		}
		units := e.withPropertySanitizers(files[i].Units)
		for u := range units {
			res := e.forwardPass(lang(i), &units[u], nil, summaries)
			for _, f := range res.flows {
				if crossesFile(&f, names) {
					flows = append(flows, f)
				}
			}
		}
	}
	sortFlows(flows)
	return onePerSink(flows)
}

// hasEffect reports whether a summary changes anything for a caller.
func hasEffect(s *funcSummary) bool {
	return len(s.sinksArg) > 0 || len(s.returnsTaintedIf) > 0 || s.returnsSource != nil || len(s.sanitizesClass) > 0
}

// crossesFile reports whether a flow went through a summary of a function in
// another file.
func crossesFile(f *taint.Flow, external map[string]bool) bool {
	for _, v := range f.Via {
		if external[v] {
			return true
		}
	}
	return false
}

// stepFunc names the function a call step is made from: a callback has no
// name of its own, and is not module code either.
func stepFunc(u *taint.Unit) string {
	if u.FuncName == "" && u.Line > 0 {
		return "<anonymous>"
	}
	return u.FuncName
}
