package deps

import (
	"context"
	"sort"
	"strings"
)

// POMCoordinate names one published pom.xml.
type POMCoordinate struct {
	Group, Artifact, Version string
}

// POMStatus is what a POMSource found for one coordinate.
type POMStatus string

const (
	// POMFound means Content is the file.
	POMFound POMStatus = "found"
	// POMNotFound means the repository has no such file, as for a company parent
	// published only to its own repository.
	POMNotFound POMStatus = "not_found"
	// POMUnavailable means the file could not be asked for. Never read as
	// POMNotFound: the next scan may well get it.
	POMUnavailable POMStatus = "unavailable"
)

// POMResult is a POMSource's answer for one coordinate.
type POMResult struct {
	Coordinate POMCoordinate
	Status     POMStatus
	Content    []byte
}

// POMSource fetches published pom.xml files. The scanner resolves versions from
// them itself; a source serves files, never a resolution. A returned error
// means none of the batch was answered.
type POMSource interface {
	FetchPOMs(ctx context.Context, coords []POMCoordinate) ([]POMResult, error)
}

// WithPOMSource lets the analyzer fetch Maven parents and BOMs the repository
// does not contain. Without one, dependencies whose version lives in such a
// file are reported unresolved, as on an offline scan.
func WithPOMSource(s POMSource) AnalyzerOption {
	return func(a *Analyzer) { a.pomSource = s }
}

// maxPOMBatch is the most coordinates asked for at once (the service's limit).
const maxPOMBatch = 64

// mavenFetch records what fetching achieved, for the degradation.
type mavenFetch struct {
	enabled     bool
	requested   int
	notFound    map[pomCoords]bool
	unavailable map[pomCoords]bool
	reason      string // the first transport or service error, if any
}

// fetchRemote asks src for every parent and BOM the index's modules need and
// does not have, in waves: a fetched parent names its own parent, and a fetched
// BOM imports others. It stops when a wave asks for nothing new, or after
// maxPomDepth waves, which no real chain approaches.
func (x *mavenIndex) fetchRemote(ctx context.Context, src POMSource) *mavenFetch {
	st := &mavenFetch{enabled: src != nil, notFound: map[pomCoords]bool{}, unavailable: map[pomCoords]bool{}}
	if src == nil {
		return st
	}
	for range maxPomDepth {
		need := x.missing(st)
		if len(need) == 0 {
			return st
		}
		for start := 0; start < len(need); start += maxPOMBatch {
			batch := need[start:min(start+maxPOMBatch, len(need))]
			coords := make([]POMCoordinate, len(batch))
			for i, c := range batch {
				coords[i] = POMCoordinate{c.group, c.artifact, c.version}
			}
			st.requested += len(coords)
			results, err := src.FetchPOMs(ctx, coords)
			if err != nil {
				if st.reason == "" {
					st.reason = err.Error()
				}
				for _, c := range batch {
					st.unavailable[c] = true
				}
				continue
			}
			answered := map[pomCoords]bool{}
			for _, r := range results {
				c := pomCoords{r.Coordinate.Group, r.Coordinate.Artifact, r.Coordinate.Version}
				answered[c] = true
				switch r.Status {
				case POMFound:
					if !x.addRemote(c, r.Content) {
						st.unavailable[c] = true
						if st.reason == "" {
							st.reason = c.String() + " was served but is not that POM"
						}
					}
				case POMNotFound:
					st.notFound[c] = true
				default:
					st.unavailable[c] = true
				}
			}
			// A coordinate the source did not mention was not answered.
			for _, c := range batch {
				if !answered[c] {
					st.unavailable[c] = true
				}
			}
		}
	}
	return st
}

// addRemote indexes a fetched POM under the coordinates it was asked for. A
// file that does not parse, or names other coordinates, resolves nothing and
// reports false: reading versions from the wrong POM would be worse than
// reading none.
func (x *mavenIndex) addRemote(c pomCoords, content []byte) bool {
	f := parsePomFile("", content)
	f.remote = true
	if f.parseFail != nil || f.coords != c {
		return false
	}
	x.remote[c] = f
	return true
}

// missing lists, in a stable order, the external parents and imported BOMs the
// repository's modules need that are neither indexed nor already asked for.
// A coordinate still holding a ${...} reference cannot be asked for.
func (x *mavenIndex) missing(st *mavenFetch) []pomCoords {
	want := map[pomCoords]bool{}
	add := func(c pomCoords) {
		if c.group == "" || c.artifact == "" || c.version == "" ||
			strings.Contains(c.group+c.artifact+c.version, "${") {
			return
		}
		if _, have := x.remote[c]; have || st.notFound[c] || st.unavailable[c] {
			return
		}
		want[c] = true
	}
	for _, f := range x.byPath {
		if f.parseFail != nil {
			continue
		}
		if _, ext := x.chain(f); ext != nil {
			add(*ext)
		}
		_, boms := x.managedVersions(f, 0, map[*pomFile]bool{})
		for _, b := range boms {
			add(b)
		}
	}
	out := make([]pomCoords, 0, len(want))
	for c := range want {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
