package findings

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
