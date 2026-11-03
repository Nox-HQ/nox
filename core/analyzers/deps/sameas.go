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
// gate reads and the work a reviewer does. Records are joined through
// nox_same_as, which the service computed over this one answer. A source that
// sends none (OSV.dev, an older service) is joined by the service's own rule:
// records in this answer that share a name, their id or an alias, are one
// vulnerability. An alias naming a record absent from the answer joins nothing.
//
// The surviving record is chosen so that collapsing can never lower what the
// scan reports and never depends on arrival order: a gating status beats a
// theoretical one, then the higher severity wins, then the smaller id. Every
// other id of the group (its id, its aliases) is kept on the survivor's
// aliases, because a waiver or baseline written against either name must keep
// matching. What reachability reads (each affected package's import paths and
// symbols, and nox_symbols) is joined from every member: in a Go answer the
// survivor is usually the GitHub advisory and the symbols are on the Go one.
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
	if linked {
		for i := range recs {
			for _, other := range recs[i].SameAs {
				if j, ok := index[other]; ok {
					parent[find(i)] = find(j)
				}
			}
		}
	} else {
		owner := map[string]int{} // a name -> the first record that carries it
		for i := range recs {
			for _, name := range append([]string{recs[i].ID}, recs[i].Aliases...) {
				if j, ok := owner[name]; ok {
					parent[find(i)] = find(j)
				} else {
					owner[name] = i
				}
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
	if len(roots) == len(recs) {
		return recs, nil // nothing joined: the list as it arrived
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
	joinReachability(&merged, recs, members)
	return merged
}

// joinReachability gives the survivor every member's import paths and symbols
// for the packages it affects, and every member's nox_symbols. A package the
// survivor does not list gains nothing: its ranges are what decide a match.
func joinReachability(merged *vulnsource.Record, recs []vulnsource.Record, members []int) {
	affected := make([]vulnsource.Affected, len(merged.Affected))
	copy(affected, merged.Affected)
	for i := range affected {
		var imports [][]vulnsource.Import
		for _, m := range members {
			for _, a := range recs[m].Affected {
				if a.Package == affected[i].Package {
					imports = append(imports, a.EcosystemSpecific.Imports)
				}
			}
		}
		affected[i].EcosystemSpecific.Imports = unionImports(imports)
	}
	merged.Affected = affected

	var symbols []vulnsource.AffectedSymbols
	seen := map[string]bool{}
	for _, m := range members {
		for _, as := range recs[m].Symbols {
			key := as.AdvisoryID + "\x00" + as.Package + "\x00" + as.FixedVersion + "\x00" + as.Method
			if !seen[key] {
				seen[key] = true
				symbols = append(symbols, as)
			}
		}
	}
	merged.Symbols = symbols
}

// unionImports joins import lists by path. A path listed without symbols means
// the whole package, and stays that way whatever another list names.
func unionImports(lists [][]vulnsource.Import) []vulnsource.Import {
	var paths []string
	whole := map[string]bool{}
	syms := map[string]map[string]struct{}{}
	for _, list := range lists {
		for _, im := range list {
			if _, ok := syms[im.Path]; !ok {
				syms[im.Path] = map[string]struct{}{}
				paths = append(paths, im.Path)
			}
			if len(im.Symbols) == 0 {
				whole[im.Path] = true
			}
			for _, s := range im.Symbols {
				syms[im.Path][s] = struct{}{}
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths)
	out := make([]vulnsource.Import, 0, len(paths))
	for _, p := range paths {
		im := vulnsource.Import{Path: p}
		if !whole[p] {
			for s := range syms[p] {
				im.Symbols = append(im.Symbols, s)
			}
			sort.Strings(im.Symbols)
		}
		out = append(out, im)
	}
	return out
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
