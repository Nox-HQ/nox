package findings

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

// Enrichment annotates an existing finding with additional context
// without modifying the original finding fields. This preserves
// determinism of the core scan engine while allowing plugins to
// layer on triage decisions, reachability analysis, or explanations.
//
// The JSON tags matter as much as the fields do. Enrichments were populated on
// ScanResult and then dropped — no reporter serialized them — so a post-scan
// plugin's entire output was computed and discarded. Any plugin emitting
// enrichments rather than findings, which is the correct shape for one that
// annotates rather than detects, was silently a no-op to every consumer
// reading findings.json.
type Enrichment struct {
	FindingFingerprint string            `json:"finding_fingerprint"` // links to Finding.Fingerprint
	Kind               string            `json:"kind"`                // "triage", "reachability", "explanation"
	Title              string            `json:"title"`
	Body               string            `json:"body,omitempty"` // markdown content
	Metadata           map[string]string `json:"metadata,omitempty"`
	Confidence         Confidence        `json:"confidence,omitempty"`
	Source             string            `json:"source,omitempty"` // plugin name that produced it
}

// SortEnrichments orders enrichments by the finding they annotate, then by
// source, kind, title, body, confidence and metadata, and returns the slice.
// Plugins return enrichments in whatever order they hold them, often a Go
// map's, and the report must not inherit it: the same tree has to give the
// same findings.json.
func SortEnrichments(es []Enrichment) []Enrichment {
	slices.SortStableFunc(es, func(a, b Enrichment) int {
		return cmp.Or(
			cmp.Compare(a.FindingFingerprint, b.FindingFingerprint),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Title, b.Title),
			cmp.Compare(a.Body, b.Body),
			cmp.Compare(string(a.Confidence), string(b.Confidence)),
			cmp.Compare(metadataKey(a.Metadata), metadataKey(b.Metadata)),
		)
	})
	return es
}

func metadataKey(m map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	return b.String()
}
