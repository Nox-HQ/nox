package deps

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/findings"
)

// collapseSameAs makes one vulnerability reported under several identifiers
// one record.
//
// NOX Intelligence merges nothing: a Go module advisory and its GitHub
// advisory both arrive, each carrying nox_same_as naming the other. Reported
// as they arrive they are two findings for one flaw, which doubles the count a
// gate reads and the work a reviewer does. Records are joined only through
// nox_same_as, which the service computed over this one answer; an alias
// listed in `aliases` that is not also in the answer joins nothing.
//
// The surviving record is chosen so that collapsing can never lower what the
// scan reports and never depends on arrival order: a gating status beats a
// theoretical one, then the higher severity wins, then the smaller id. Every
// other id of the group (its id, its aliases) is kept on the survivor's
// aliases, because a waiver or baseline written against either name must keep
// matching. A source that sends no nox_same_as (OSV.dev, an older service)
// leaves the list untouched.
//
// The second result maps each survivor's id to the records it absorbed, as they
// arrived, so the caller can recover what their findings used to be.
func collapseSameAs(recs []vulnsource.Record) (survivors []vulnsource.Record, absorbed map[string][]vulnsource.Record) {
	linked := false
	for i := range recs {
		if len(recs[i].SameAs) > 0 {
			linked = true
			break
		}
	}
	if !linked {
		return recs, nil
	}

	index := make(map[string]int, len(recs))
	for i := range recs {
		if _, dup := index[recs[i].ID]; !dup {
			index[recs[i].ID] = i
		}
	}
	parent := make([]int, len(recs))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	for i := range recs {
		for _, other := range recs[i].SameAs {
			if j, ok := index[other]; ok {
				parent[find(i)] = find(j)
			}
		}
	}

	groups := map[int][]int{}
	var roots []int
	for i := range recs {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], i)
	}

	out := make([]vulnsource.Record, 0, len(groups))
	absorbed = map[string][]vulnsource.Record{}
	for _, r := range roots {
		merged := mergeGroup(recs, groups[r])
		out = append(out, merged)
		for _, m := range groups[r] {
			if recs[m].ID != merged.ID {
				absorbed[merged.ID] = append(absorbed[merged.ID], recs[m])
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, absorbed
}

func mergeGroup(recs []vulnsource.Record, members []int) vulnsource.Record {
	if len(members) == 1 {
		return recs[members[0]]
	}
	best := members[0]
	for _, m := range members[1:] {
		if betterRecord(&recs[m], &recs[best]) {
			best = m
		}
	}
	merged := recs[best]

	names := map[string]struct{}{}
	var prov []vulnsource.Provenance
	var disagree []string
	for _, m := range members {
		r := recs[m]
		names[r.ID] = struct{}{}
		for _, a := range r.Aliases {
			names[a] = struct{}{}
		}
		prov = append(prov, r.Provenance...)
		disagree = append(disagree, r.Disagreement...)
	}
	delete(names, merged.ID)
	merged.Aliases = nil
	for n := range names {
		merged.Aliases = append(merged.Aliases, n)
	}
	sort.Strings(merged.Aliases)
	merged.Provenance = dedupProvenance(prov)
	merged.Disagreement = dedupStrings(disagree)
	merged.SameAs = nil
	return merged
}

// betterRecord reports whether a should represent the group in place of b.
func betterRecord(a, b *vulnsource.Record) bool {
	if ga, gb := a.Status().Gating(), b.Status().Gating(); ga != gb {
		return ga
	}
	sa := findings.SeverityRank(mapOSVSeverity(a.Severity, a.DatabaseSpecific))
	sb := findings.SeverityRank(mapOSVSeverity(b.Severity, b.DatabaseSpecific))
	if sa != sb {
		return sa < sb
	}
	return a.ID < b.ID
}

func dedupProvenance(in []vulnsource.Provenance) []vulnsource.Provenance {
	seen := map[vulnsource.Provenance]struct{}{}
	var out []vulnsource.Provenance
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Via != b.Via {
			return a.Via < b.Via
		}
		if a.RetrievedAt != b.RetrievedAt {
			return a.RetrievedAt < b.RetrievedAt
		}
		return a.Modified < b.Modified
	})
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// addProvenanceMetadata records which source answered and by what path, in
// terms that are the same on every run of the same answer.
//
// A live retrieval's time is the moment of the request, i.e. the wall clock,
// and findings.json must not change between two scans of one tree, so it is
// not written. A mirror's time is the corpus sync time, which is a property of
// the answer (how stale it can be) and is.
func addProvenanceMetadata(meta map[string]string, r *vulnsource.Record) {
	if len(r.Provenance) == 0 {
		return
	}
	prov := dedupProvenance(r.Provenance)
	var sources, vias []string
	var synced string
	for _, p := range prov {
		sources = append(sources, p.Source)
		vias = append(vias, p.Via)
		if p.Via == "mirror" && p.RetrievedAt > synced {
			synced = p.RetrievedAt
		}
	}
	meta["advisory_source"] = strings.Join(dedupStrings(sources), ",")
	meta["advisory_via"] = strings.Join(dedupStrings(vias), ",")
	if synced != "" {
		meta["advisory_mirror_synced_at"] = synced
	}
	if len(r.Disagreement) > 0 {
		meta["advisory_disagreement"] = strings.Join(dedupStrings(r.Disagreement), ",")
	}
}
