package findings

// Enrichment annotates an existing finding with additional context
// without modifying the original finding fields. This preserves
// determinism of the core scan engine while allowing plugins to
// layer on triage decisions, reachability analysis, or explanations.
type Enrichment struct {
	FindingFingerprint string // links to Finding.Fingerprint
	Kind               string // "triage", "reachability", "explanation"
	Title              string
	Body               string // markdown content
	Metadata           map[string]string
	Confidence         Confidence
	Source             string // plugin name that produced it
}
