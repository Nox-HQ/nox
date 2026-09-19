package engine

import (
	"sort"

	"github.com/nox-hq/nox/core/taint"
)

// SinkSite is one call to a catalog sink, whatever reaches it.
type SinkSite struct {
	Class    taint.VulnClass `json:"class"`
	Call     string          `json:"call"`
	FilePath string          `json:"file"`
	Line     int             `json:"line"`
}

// SinkSites lists the catalog sink calls in units, one per (class, call),
// keeping the first site in file and line order.
//
// It answers a different question from Analyze: not "does untrusted input reach
// this sink?" but "does this code call it at all?". A service that runs
// exec.Command holds the authority to execute commands whether or not any input
// reaches the call, and so does every dependency running inside it — which is
// what a blast radius asks about.
func (e *StructuralEngine) SinkSites(units []taint.Unit) []SinkSite {
	seen := map[[2]string]bool{}
	var out []SinkSite
	for i := range units {
		u := &units[i]
		for j := range u.Stmts {
			st := &u.Stmts[j]
			for _, call := range st.Calls {
				sink, ok := e.resolveSink(u.Language, call)
				if !ok {
					continue
				}
				key := [2]string{string(sink.VulnClass), sink.Call}
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, SinkSite{Class: sink.VulnClass, Call: sink.Call, FilePath: u.FilePath, Line: st.Line})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].Call < out[j].Call
	})
	return out
}
