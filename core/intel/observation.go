package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Observation is one security fact this installation is willing to share.
//
// The struct IS the allowlist. There is no "extra" map, no passthrough field,
// and no embedded original finding — a field that is not declared here cannot
// be transmitted, which is what makes the guarantee structural rather than a
// matter of remembering to strip things.
type Observation struct {
	Fingerprint string `json:"fingerprint"`

	Ecosystem    string `json:"ecosystem"`
	Package      string `json:"package"`
	VersionRange string `json:"version_range"`
	Weakness     string `json:"weakness"`
	RuleID       string `json:"rule_id"`

	ReporterID  string `json:"reporter_id,omitempty"`
	ObservedAt  string `json:"observed_at"`
	ToolVersion string `json:"tool_version,omitempty"`
}

// Fingerprint derives the clustering key from the shareable facts.
//
// It must agree byte for byte with the service's own derivation, because the
// service recomputes it on ingest and rejects an observation whose fingerprint
// does not follow from the facts beside it. That check is what stops a reporter
// placing an observation into a cluster of its choosing — the cheapest possible
// poisoning attack, needing no volume and no Sybils, just a wrong hash.
//
// Normalisation is deliberate and lossy: case and surrounding whitespace carry
// no security meaning, and leaving them significant would split one logical
// issue into several clusters, each too small to corroborate. That failure is
// silent — the network would simply never reach a confident verdict and would
// look merely quiet rather than broken.
func Fingerprint(ecosystem, pkg, versionRange, weakness, ruleID string) string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	sum := sha256.Sum256([]byte(strings.Join([]string{
		norm(ecosystem), norm(pkg), norm(versionRange), norm(weakness), norm(ruleID),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// DeriveOptions supplies the values a caller must decide rather than the
// package inventing them.
type DeriveOptions struct {
	// ReporterID is this installation's opaque identifier. Empty means the
	// observations are unattributed, and the service will never count them
	// toward independence.
	ReporterID string
	// ObservedAt is an RFC3339 timestamp. The package never reads a clock, so
	// a derivation is reproducible and a replayed contribution is identical.
	ObservedAt string
	// ToolVersion identifies this build.
	ToolVersion string
}

// Derive turns findings into observations.
//
// Only dependency findings are eligible. Every other rule family reports on the
// operator's own code — a taint path, a hardcoded secret, an unsafe tool
// exposure — and the fact that it exists is a fact about their codebase, not
// about a package the ecosystem shares. Those never leave, whatever the
// contribution mode.
func Derive(fs []findings.Finding, opts DeriveOptions) []Observation {
	seen := make(map[string]struct{}, len(fs))
	out := make([]Observation, 0, len(fs))

	for i := range fs {
		f := &fs[i]
		if !eligible(f) {
			continue
		}

		eco := f.Metadata["ecosystem"]
		pkg := f.Metadata["package"]
		if eco == "" || pkg == "" {
			continue
		}

		o := Observation{
			Ecosystem:    eco,
			Package:      pkg,
			VersionRange: versionRange(f),
			Weakness:     f.Metadata["weakness"],
			RuleID:       f.RuleID,
			ReporterID:   opts.ReporterID,
			ObservedAt:   opts.ObservedAt,
			ToolVersion:  opts.ToolVersion,
		}
		o.Fingerprint = Fingerprint(o.Ecosystem, o.Package, o.VersionRange, o.Weakness, o.RuleID)

		// One installation reporting the same logical issue twice in one scan
		// is still one sighting. Collapsing here keeps a monorepo that vendors
		// a package in twelve places from looking like twelve reports.
		if _, dup := seen[o.Fingerprint]; dup {
			continue
		}
		seen[o.Fingerprint] = struct{}{}
		out = append(out, o)
	}
	return out
}

// eligibleRules is the set of rules whose findings describe a shared package
// rather than the operator's own code.
var eligibleRules = map[string]struct{}{
	"VULN-001": {},
}

func eligible(f *findings.Finding) bool {
	_, ok := eligibleRules[f.RuleID]
	return ok
}

// versionRange expresses the affected range as this installation understands
// it. A known fix gives a real upper bound; without one there is nothing
// truthful to say, and inventing a range would fabricate a security fact.
func versionRange(f *findings.Finding) string {
	if fixed := f.Metadata["fixed_in"]; fixed != "" {
		return "<" + fixed
	}
	return ""
}
