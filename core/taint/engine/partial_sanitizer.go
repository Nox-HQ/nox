package engine

import (
	"strings"

	"github.com/nox-hq/nox/core/taint"
)

// A partial sanitizer is one the catalog marks requires_guard: a canonicalizer
// such as filepath.Clean, os.path.realpath or path.resolve. Canonicalizing does
// not contain a path — Clean("../../etc/passwd") is still "../../etc/passwd" —
// it only makes the allow-base check that follows it sound. So its classes are
// cleared on a variable only when a check (catalog "checks": strings.HasPrefix,
// startswith, startsWith, …) reads that variable in a branch condition of the
// same function, at or after the line that produced it.
//
// The canonicalizer only has to appear in the statement that produced the
// variable, not strictly around the source: `Paths.get(src).normalize()` chains
// it after, and the check on the result is the defence either way.
//
// Within one function and without a CFG, "a check reads it" is the evidence
// available: it does not prove the check refuses on every path, only that the
// author paired the canonicalizer with one. That is the pairing the catalog
// notes have always required, now enforced instead of assumed.

// checkIndex records, per vuln class, the variables a check reads and the
// lines it reads them on.
type checkIndex map[taint.VulnClass]map[string][]int

// partialClasses returns the classes the statement's calls would clear only as
// partial sanitizers.
func (e *StructuralEngine) partialClasses(lang string, calls []string) map[taint.VulnClass]bool {
	out := map[taint.VulnClass]bool{}
	for _, rawCall := range calls {
		for _, key := range suffixKeys(rawCall) {
			found := false
			for _, class := range allVulnClasses {
				if e.cat.IsPartialSanitizer(lang, key, class) {
					out[class] = true
					found = true
				}
			}
			if found {
				break
			}
		}
	}
	return out
}

// checkedValues indexes the checks in a unit. Branch conditions arrive as
// Guards from the extractors that keep conditions out of Stmts; Python's
// recognizer emits a condition as an ordinary statement, so Stmts are indexed
// too. Only calls the catalog lists as checks count, so an ordinary statement
// contributes nothing unless it is one.
func (e *StructuralEngine) checkedValues(lang string, unit *taint.Unit) checkIndex {
	idx := checkIndex{}
	add := func(line int, calls, reads []string) {
		for _, rawCall := range calls {
			classes := e.checkClasses(lang, rawCall)
			if len(classes) == 0 {
				continue
			}
			vars := append([]string(nil), reads...)
			// A method check reads its receiver: p.startswith(base).
			if dot := strings.IndexByte(rawCall, '.'); dot > 0 {
				vars = append(vars, rawCall[:dot])
			}
			for _, class := range classes {
				if idx[class] == nil {
					idx[class] = map[string][]int{}
				}
				for _, v := range vars {
					idx[class][v] = append(idx[class][v], line)
				}
			}
		}
	}
	for _, g := range unit.Guards {
		add(g.Line, g.Calls, g.Reads)
	}
	for _, st := range unit.Stmts {
		add(st.Line, st.Calls, st.Reads)
	}
	return idx
}

// checkClasses returns the classes a call completes as a check (by suffix
// match, first matching suffix wins, like sanitizer resolution).
func (e *StructuralEngine) checkClasses(lang, rawCall string) []taint.VulnClass {
	var out []taint.VulnClass
	for _, key := range suffixKeys(rawCall) {
		for _, class := range allVulnClasses {
			if e.cat.IsCheck(lang, key, class) {
				out = append(out, class)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

// covers reports whether a check for class reads v at or after line.
func (idx checkIndex) covers(class taint.VulnClass, v string, line int) bool {
	for _, l := range idx[class][v] {
		if l >= line {
			return true
		}
	}
	return false
}

// admit adds to cleared each candidate class that a check covers for v.
func (idx checkIndex) admit(cleared map[taint.VulnClass]bool, v string, line int, candidates map[taint.VulnClass]bool) {
	for class := range candidates {
		if !cleared[class] && idx.covers(class, v, line) {
			cleared[class] = true
		}
	}
}
