package core

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/report"
)

// Scopes: what a scan looks at.
//
// A full scan runs every analyzer. A scope narrows it to one concern -- only
// secrets, only code, only dependencies -- so nox can stand in for a
// single-purpose tool in a pipeline that only wants that, at that tool's cost.
// The narrowing happens before any work: an analyzer outside the scope is never
// constructed or run, and a stage that only serves other scopes (vulnerability
// lookups, the SBOM, the AI inventory) does not run either. Filtering findings
// afterwards would cost the full scan and save nothing.
//
// What did not run is recorded on the result (ScanResult.Scope) and in every
// output, because a scoped scan with no dependency findings has not shown that
// the dependencies are clean -- it never looked at them.

// Scope names one concern a scan can be narrowed to.
type Scope string

// The scopes, one per concern. analyzerScope says which analyzers each runs.
const (
	ScopeSecrets     Scope = "secrets"
	ScopeCode        Scope = "code"
	ScopeDeps        Scope = "deps"
	ScopeIaC         Scope = "iac"
	ScopeAI          Scope = "ai"
	ScopeData        Scope = "data"
	ScopeSupplyChain Scope = "supply-chain"
)

// allScopes is every scope, in the order outputs list them.
var allScopes = []Scope{ScopeSecrets, ScopeCode, ScopeDeps, ScopeIaC, ScopeAI, ScopeData, ScopeSupplyChain}

// analyzerScope assigns each built-in analyzer to the one scope it serves.
// rulePatterns is what skip_analyzer removes for that analyzer.
var analyzerScope = map[string]struct {
	scope        Scope
	rulePatterns []string
}{
	"secrets":    {ScopeSecrets, []string{"SEC-*"}},
	"taintflow":  {ScopeCode, []string{"TAINT-*"}},
	"agentflow":  {ScopeCode, []string{"AGENTFLOW-*"}},
	"variants":   {ScopeCode, []string{"VARIANT-*"}},
	"weakcrypto": {ScopeCode, []string{"CRYPTO-*"}},
	"hardening":  {ScopeCode, []string{"HARDEN-*"}},
	"memsafe":    {ScopeCode, []string{"MEMSAFE-*"}},
	"deps":       {ScopeDeps, []string{"VULN-*", "CONT-*", "LIC-*"}},
	"iac":        {ScopeIaC, []string{"IAC-*"}},
	"fileperms":  {ScopeIaC, []string{"PERM-*"}},
	"ai":         {ScopeAI, []string{"AI-*", "MCP-*", "AGENT-*"}},
	"data":       {ScopeData, []string{"DATA-*"}},
	"slop":       {ScopeSupplyChain, []string{"SLOP-*"}},
	"provenance": {ScopeSupplyChain, []string{"PROV-*"}},
}

// ScopeSet is the set of scopes a scan runs. The zero value is a full scan.
type ScopeSet struct {
	only map[Scope]bool // nil: every scope
}

// FullScope is every scope.
func FullScope() ScopeSet { return ScopeSet{} }

// ResolveScopes turns --only/--skip (or scan.analyzers) into a ScopeSet.
// Unknown names are an error: a typo in a scope must not silently become a
// scan of nothing, or of everything.
func ResolveScopes(only, skip []string) (ScopeSet, error) {
	parse := func(names []string) (map[Scope]bool, error) {
		out := map[Scope]bool{}
		for _, n := range names {
			n = strings.TrimSpace(strings.ToLower(n))
			if n == "" {
				continue
			}
			s := Scope(n)
			if !isScope(s) {
				return nil, fmt.Errorf("unknown scope %q (valid: %s)", n, scopeNames(allScopes))
			}
			out[s] = true
		}
		return out, nil
	}
	o, err := parse(only)
	if err != nil {
		return ScopeSet{}, err
	}
	k, err := parse(skip)
	if err != nil {
		return ScopeSet{}, err
	}
	if len(o) == 0 && len(k) == 0 {
		return FullScope(), nil
	}
	set := map[Scope]bool{}
	for _, s := range allScopes {
		if (len(o) == 0 || o[s]) && !k[s] {
			set[s] = true
		}
	}
	if len(set) == 0 {
		return ScopeSet{}, fmt.Errorf("--only/--skip leave no scope to scan")
	}
	return ScopeSet{only: set}, nil
}

func isScope(s Scope) bool {
	for _, a := range allScopes {
		if a == s {
			return true
		}
	}
	return false
}

// Full reports whether every scope runs.
func (s ScopeSet) Full() bool { return s.only == nil }

// Has reports whether scope runs.
func (s ScopeSet) Has(scope Scope) bool { return s.only == nil || s.only[scope] }

// RunsAnalyzer reports whether the named built-in analyzer runs.
func (s ScopeSet) RunsAnalyzer(name string) bool {
	a, ok := analyzerScope[name]
	if !ok {
		return s.Full()
	}
	return s.Has(a.scope)
}

// WaiverRulesRan reports whether any rule a waiver names could have produced a
// finding in this scan, so that an unmatched waiver means something. In a full
// scan every rule ran. In a scoped scan a blanket waiver (no rule IDs) is never
// evidence, and a rule ID no scope owns -- a custom rule -- ran, since custom
// rules run in every scan.
func (s ScopeSet) WaiverRulesRan(ruleIDs []string) bool {
	if s.Full() {
		return true
	}
	for _, id := range ruleIDs {
		if s.ruleRan(id) {
			return true
		}
	}
	return false
}

// ruleRan reports whether rule id (or a wildcard such as SEC-*) belongs to a
// scope that ran, or to no scope at all.
func (s ScopeSet) ruleRan(id string) bool {
	family, _, _ := strings.Cut(strings.ToUpper(id), "-")
	for _, a := range analyzerScope {
		for _, p := range a.rulePatterns {
			if strings.TrimSuffix(p, "-*") == family {
				return s.Has(a.scope)
			}
		}
	}
	return true
}

// Ran lists the scopes that ran, in output order.
func (s ScopeSet) Ran() []Scope { return s.filter(true) }

// Skipped lists the scopes that did not run, in output order.
func (s ScopeSet) Skipped() []Scope { return s.filter(false) }

func (s ScopeSet) filter(ran bool) []Scope {
	var out []Scope
	for _, sc := range allScopes {
		if s.Has(sc) == ran {
			out = append(out, sc)
		}
	}
	return out
}

func scopeNames(ss []Scope) string {
	names := make([]string, len(ss))
	for i, s := range ss {
		names[i] = string(s)
	}
	return strings.Join(names, ", ")
}

// analyzerRulePatterns returns the rule-ID patterns a named analyzer emits,
// for the skip_analyzer action. Unknown names return nil, a no-op.
func analyzerRulePatterns(analyzer string) []string {
	return analyzerScope[analyzer].rulePatterns
}

// scopeRulePatterns returns the rule-ID patterns every analyzer of the scope
// emits, sorted.
func scopeRulePatterns(scope Scope) []string {
	var out []string
	for _, a := range analyzerScope {
		if a.scope == scope {
			out = append(out, a.rulePatterns...)
		}
	}
	sort.Strings(out)
	return out
}

// report is the scope as the outputs state it; nil for a full scan.
func (s ScopeSet) report() *report.ScanScope {
	if s.Full() {
		return nil
	}
	names := func(ss []Scope) []string {
		out := make([]string, len(ss))
		for i, x := range ss {
			out[i] = string(x)
		}
		return out
	}
	return &report.ScanScope{Scanned: names(s.Ran()), NotScanned: names(s.Skipped())}
}
