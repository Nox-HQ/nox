package attack

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// Correlation joins a static finding to whatever dynamic validation exercised it.
// It keeps the two claims strictly separate — StaticFlag says nox flagged the
// finding statically, Exploitability says what the attack loop demonstrated — so
// a reader is never misled into treating a pattern match as a proven exploit, nor
// a proven exploit as merely flagged.
type Correlation struct {
	// Fingerprint identifies the finding.
	Fingerprint string `json:"fingerprint"`
	// RuleID is the finding's rule.
	RuleID string `json:"rule_id"`
	// StaticFlag is always true: this row exists because the scan flagged it.
	StaticFlag bool `json:"static_flag"`
	// Exploitability is the dynamic verdict, or POTENTIAL if no trace ran.
	Exploitability evidence.Exploitability `json:"exploitability"`
	// Confidence is the dynamic confidence, or LOW if no trace ran.
	Confidence evidence.Confidence `json:"confidence"`
	// TraceID links to the trace that produced the dynamic verdict, or "".
	TraceID string `json:"trace_id,omitempty"`
	// AttackPath renders the trace's path, or "" if no trace ran.
	AttackPath string `json:"attack_path,omitempty"`
	// Description is a human-readable summary.
	Description string `json:"description"`
}

// Correlate merges static findings with dynamic traces into one row per finding.
// A finding exercised by several traces takes the most-established one, so static
// and dynamic knowledge combine without double-counting. Findings never exercised
// stay POTENTIAL — flagged, but not validated. Output is sorted deterministically.
func Correlate(fs []findings.Finding, r *Result) []Correlation {
	best := map[string]*Trace{}
	if r != nil {
		for i := range r.Traces {
			tr := &r.Traces[i]
			for _, fp := range tr.FindingFingerprints {
				cur, ok := best[fp]
				if !ok || tr.Exploitability.AtLeast(cur.Exploitability) {
					best[fp] = tr
				}
			}
		}
	}

	out := make([]Correlation, 0, len(fs))
	for i := range fs {
		f := fs[i]
		c := Correlation{
			Fingerprint:    f.Fingerprint,
			RuleID:         f.RuleID,
			StaticFlag:     true,
			Exploitability: evidence.Potential,
			Confidence:     evidence.ConfidenceLow,
			Description:    "flagged statically; no dynamic attack path exercised it",
		}
		if tr, ok := best[f.Fingerprint]; ok {
			c.Exploitability = tr.Exploitability
			c.Confidence = tr.Confidence
			c.TraceID = tr.ID
			c.AttackPath = renderPath(tr.Path)
			c.Description = "flagged statically; dynamic verdict " + string(tr.Exploitability)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Fingerprint != out[j].Fingerprint {
			return out[i].Fingerprint < out[j].Fingerprint
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// renderPath renders an attack path as "label -> label -> ...".
func renderPath(steps []PathStep) string {
	if len(steps) == 0 {
		return ""
	}
	labels := make([]string, 0, len(steps))
	for _, s := range steps {
		labels = append(labels, s.Label)
	}
	return strings.Join(labels, " -> ")
}
