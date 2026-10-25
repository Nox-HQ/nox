package mcpfeed

import (
	"sort"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/mcpconfig"
)

// Server is one MCP server definition whose package could be identified.
type Server struct {
	// Config is the repository-relative path of the client config defining it.
	Config string
	// Line locates the server in Config (1 when unknown).
	Line int
	// Name is the key the config gives the server.
	Name string
	// Package is what its launch fetches from a registry.
	Package mcpconfig.PackageRef
}

// Mode says how much a Hit can be trusted to mean "this version".
type Mode string

const (
	// ModeRange means the server pins an exact version and the entry's own interval
	// contains it. An advisory covers this version.
	ModeRange Mode = "range"
	// ModeUnevaluated means the server pins an exact version, but the entry gives no
	// interval nox can evaluate (a candidate's free-text version_range, or no
	// range at all). The package is named by an advisory; whether THIS version
	// is covered is not established.
	ModeUnevaluated Mode = "unevaluated"
	// ModeUnpinned means the server launches whatever the registry serves today, so
	// no interval can be tested. Advisories exist for the package; whether the
	// version that will run is covered cannot be said.
	ModeUnpinned Mode = "unpinned"
)

// Hit is the join of one server with the feed's entries for its package.
type Hit struct {
	Server  Server
	Mode    Mode
	Entries []Entry
}

// Check joins servers with the feed on (ecosystem, package). It reports only
// what the feed says: a server with no entries yields nothing, which is not a
// statement that its package is free of advisories.
func (f *Feed) Check(servers []Server) []Hit {
	type key struct{ eco, name string }
	byPkg := map[key][]Entry{}
	for _, e := range f.Entries {
		k := key{canonicalEcosystem(e.Ecosystem), mcpconfig.NormalizeName(e.Ecosystem, e.Package)}
		byPkg[k] = append(byPkg[k], e)
	}

	ordered := append([]Server(nil), servers...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.Config != b.Config {
			return a.Config < b.Config
		}
		return a.Name < b.Name
	})

	var hits []Hit
	for _, s := range ordered {
		entries := byPkg[key{canonicalEcosystem(s.Package.Ecosystem), mcpconfig.NormalizeName(s.Package.Ecosystem, s.Package.Name)}]
		if len(entries) == 0 {
			continue
		}
		sortEntries(entries)
		if !s.Package.Pinned {
			hits = append(hits, Hit{Server: s, Mode: ModeUnpinned, Entries: entries})
			continue
		}
		var covered, unevaluated []Entry
		for _, e := range entries {
			switch coverage(e, s.Package.Version) {
			case coversVersion:
				covered = append(covered, e)
			case cannotEvaluate:
				unevaluated = append(unevaluated, e)
			}
		}
		if len(covered) > 0 {
			hits = append(hits, Hit{Server: s, Mode: ModeRange, Entries: covered})
		}
		if len(unevaluated) > 0 {
			hits = append(hits, Hit{Server: s, Mode: ModeUnevaluated, Entries: unevaluated})
		}
	}
	return hits
}

type verdict int

const (
	outsideRanges verdict = iota
	coversVersion
	cannotEvaluate
)

// coverage tests one pinned version against an entry's own intervals, with
// nox-core's version ordering. A version that cannot be ordered is never
// treated as covered (Interval.Covers), and an entry with nothing to test is
// reported as unevaluated rather than as outside.
func coverage(e Entry, version string) verdict {
	if len(e.Ranges) == 0 {
		return cannotEvaluate
	}
	if !vulnsource.ComparableVersion(version) {
		return cannotEvaluate
	}
	for _, r := range e.Ranges {
		if (vulnsource.Interval{Introduced: r.Introduced, Fixed: r.Fixed, LastAffected: r.LastAffected}).Covers(version) {
			return coversVersion
		}
	}
	return outsideRanges
}

func canonicalEcosystem(e string) string {
	n := mcpconfig.NormalizeName("", e)
	if n == "pypi" {
		return mcpconfig.EcosystemPyPI
	}
	return n
}

func sortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].AdvisoryID != es[j].AdvisoryID {
			return es[i].AdvisoryID < es[j].AdvisoryID
		}
		return es[i].Kind < es[j].Kind
	})
}
