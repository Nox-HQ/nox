package structural

import (
	"fmt"
	"sort"
)

// An Index is the resources of MANY files, which is what a cross-resource rule
// actually needs to answer.
//
// # The false positive this removes
//
// Companion resolution asks whether a resource is protected by a different
// object: a Deployment by a PodDisruptionBudget, a Namespace by a
// ResourceQuota. Within one file it answers well. But a document set is what
// one file contains, and real manifests are not written that way — a Helm
// chart, a kustomize base, or a plain manifest directory puts each object in
// its own file, which is the layout every Kubernetes tutorial teaches.
//
// So the common case was a false positive. Measured on a two-file tree — a
// Deployment in `deployment.yaml`, a PodDisruptionBudget in `pdb.yaml` whose
// selector matches it exactly — IAC-132 reported the workload as unprotected
// and said "the document set declares no PodDisruptionBudget". The budget was
// right there, one file over.
//
// # Why this only ever removes findings
//
// The index is consulted AFTER the per-file verdict, and only for a subject the
// per-file pass already called absent. It can refute such a finding; it can
// never create one. That direction is deliberate: a scan that saw more files
// should be able to clear a resource it previously flagged, and must not be
// able to flag one it previously cleared, because the second would make a
// finding depend on which directory the operator happened to point at.
//
// # What it still cannot say
//
// Only files this scan read are in the index. A PodDisruptionBudget outside the
// scanned tree is invisible, exactly as before, and the claim says "among the
// manifests scanned" rather than "in this cluster". Narrowing the scan narrows
// what can be refuted, never what can be reported.
type Index struct {
	// entries hold each parsed file's resources, keyed by the path they came
	// from so a companion can be reported with its location and so a resource
	// never binds to itself across a duplicate read.
	entries []indexEntry
}

type indexEntry struct {
	path      string
	resources []Resource
}

// NewIndex returns an empty index.
func NewIndex() *Index { return &Index{} }

// Add parses content and records whatever resources it contains.
//
// Content that does not parse, or that parses into a schema this package does
// not model, contributes nothing and is not an error: the index is a best
// effort at "what else did this scan see", and a file it cannot read simply
// does not participate.
func (ix *Index) Add(path string, content []byte) {
	if ix == nil {
		return
	}
	docs, err := Parse(content)
	if err != nil {
		return
	}
	resources := Resources(docs)
	if len(resources) == 0 {
		return
	}
	ix.entries = append(ix.entries, indexEntry{path: path, resources: resources})
}

// Len reports how many files contributed resources.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.entries)
}

// Files returns the paths that contributed, sorted, so a caller can state what
// the index actually covered rather than implying it covered everything.
func (ix *Index) Files() []string {
	if ix == nil {
		return nil
	}
	out := make([]string, 0, len(ix.entries))
	for _, e := range ix.entries {
		out = append(out, e.path)
	}
	sort.Strings(out)
	return out
}

// CompanionElsewhere reports whether any resource in another file binds to
// subject under c, and where it was found.
//
// `excludePath` is the file the subject came from: that file's verdict has
// already been decided by the per-file pass, and re-consulting it here could
// only repeat the same answer.
//
// An UNDECIDABLE linkage returns false. Within a file, an undecidable pair
// takes the whole verdict back to the text path, because the per-file answer
// would otherwise be silently incomplete. Here the per-file answer already
// exists and this is only asked to refute it, so "I cannot tell whether that
// budget covers this workload" leaves the finding standing — the conservative
// direction, and the same one the rest of this package takes.
func (ix *Index) CompanionElsewhere(subject Resource, excludePath string, c Companion) (Hit, bool) {
	if ix == nil || len(c.Types) == 0 || c.Link == "" {
		return Hit{}, false
	}
	// Deterministic order: a scan over the same tree must refute on the same
	// companion every time, because the companion's name goes into the claim.
	entries := make([]indexEntry, len(ix.entries))
	copy(entries, ix.entries)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	for _, e := range entries {
		if e.path == excludePath {
			continue
		}
		all := e.resources
		for _, comp := range OfTypes(all, c.Types) {
			if c.resolve(subject, comp, all) != linked {
				continue
			}
			return Hit{
				Type: subject.Type, Name: subject.Name, Line: subject.Line,
				Family:        subject.Family,
				Companion:     c.Types[0],
				CompanionName: comp.Name,
				Property:      e.path,
			}, true
		}
	}
	return Hit{}, false
}

// HasType reports whether any file in the index declares a resource of one of
// these types, excluding the subject's own file.
//
// It answers a narrower question than CompanionElsewhere and exists for
// honesty rather than for verdicts: when a finding survives the cross-file
// pass, an operator should be able to tell "nothing of this kind was scanned"
// from "one was scanned and it does not cover this resource". Both leave the
// finding standing, and they are very different things to read.
func (ix *Index) HasType(types []string, excludePath string) bool {
	if ix == nil {
		return false
	}
	for _, e := range ix.entries {
		if e.path == excludePath {
			continue
		}
		if len(OfTypes(e.resources, types)) > 0 {
			return true
		}
	}
	return false
}

// ResourceAt returns the resource declared at line in content, or false.
//
// A cross-file check starts from a finding, and a finding carries a line. This
// is what turns the second back into the first without threading resource
// identity through the whole matcher.
func ResourceAt(content []byte, line int) (Resource, bool) {
	docs, err := Parse(content)
	if err != nil {
		return Resource{}, false
	}
	for _, r := range Resources(docs) {
		if r.Line == line {
			return r, true
		}
	}
	return Resource{}, false
}

// CrossFileStatement renders what the index established, naming the file the
// companion was found in.
//
// It says "among the manifests scanned" on purpose. The index holds what this
// scan read and nothing else, and a claim that implied otherwise would be
// asserting something about a cluster from a directory listing.
func (h Hit) CrossFileStatement() string {
	name := h.Name
	if name == "" {
		name = "an unnamed resource"
	}
	companion := h.CompanionName
	if companion == "" {
		companion = "an unnamed resource"
	}
	return fmt.Sprintf(
		"the %s resource %q (%s) is bound to the %s %q declared in %s, which was found among the manifests scanned rather than in this file",
		h.Family, name, h.Type, h.Companion, companion, h.Property)
}
