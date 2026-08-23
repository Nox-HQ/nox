package intel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/evidence"
)

// VersionRange is one contiguous affected span from an advisory: versions from
// Introduced (inclusive) up to Fixed (exclusive). An empty Fixed means the
// range is still unfixed, matching OSV's event model.
type VersionRange struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Advisory is a published vulnerability record, in the shape nox's ingestion
// side needs it.
//
// It is populated by the caller — the CLI reads OSV, this package never does.
// core/intel makes no network calls at all, so an offline scan behaves exactly
// like an online one apart from how much advisory data it was handed.
type Advisory struct {
	// ID is the primary identifier (OSV, GHSA, GO, ...).
	ID string `json:"id"`
	// Aliases are equivalent identifiers for the same vulnerability, typically
	// including the CVE. Correlating through them is what stops one defect from
	// becoming three candidates.
	Aliases []string `json:"aliases,omitempty"`
	// Ecosystem and Package name the affected artifact.
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	// Summary is the advisory's own one-line description.
	Summary string `json:"summary,omitempty"`
	// Severity is the advisory's severity label or vector.
	Severity string `json:"severity,omitempty"`
	// Ranges are the affected version spans.
	Ranges []VersionRange `json:"ranges,omitempty"`
	// Published is an RFC3339 publication timestamp.
	Published string `json:"published,omitempty"`
}

// Covers reports whether version falls inside any of the advisory's ranges.
//
// Two cases deliberately answer false rather than guessing:
//
//   - An advisory with no ranges. OSV reads an absent range as "unbounded", but
//     correlation here attaches a KindPublicAdvisory claim, which is strong
//     enough to carry a candidate to CONFIRMED on its own. Auto-attaching an
//     unbounded advisory would therefore confirm every version of the package
//     from a record that never actually named one.
//   - A version nox cannot order (a git SHA, "latest", an empty string).
//     Guessing at an ordering is how a fixed release gets reported as
//     vulnerable.
func (a Advisory) Covers(version string) bool {
	v := normalizeVersion(version)
	if v == "" || !comparableVersion(v) || len(a.Ranges) == 0 {
		return false
	}
	for _, r := range a.Ranges {
		if rangeCoversVersion(r, v) {
			return true
		}
	}
	return false
}

// rangeCoversVersion evaluates one [introduced, fixed) span.
func rangeCoversVersion(r VersionRange, v string) bool {
	intro := normalizeVersion(r.Introduced)
	fixed := normalizeVersion(r.Fixed)
	// "0" is OSV's "since the beginning"; comparing against it directly would
	// exclude prereleases that sort below 0.0.0.
	if intro != "" && intro != "0" {
		if !comparableVersion(intro) || compareVersions(v, intro) < 0 {
			return false
		}
	}
	if fixed != "" {
		return comparableVersion(fixed) && compareVersions(v, fixed) < 0
	}
	return true
}

// identifiers returns the advisory's primary id and aliases.
func (a Advisory) identifiers() []string {
	out := make([]string, 0, len(a.Aliases)+1)
	if a.ID != "" {
		out = append(out, a.ID)
	}
	out = append(out, a.Aliases...)
	return out
}

// CorrelateAdvisories attaches every advisory that explains the candidate and
// reports whether any did.
//
// An advisory matches when it names the same artifact AND covers a version the
// candidate was observed at, or when it shares an identifier the candidate is
// already correlated with — alias matching is what keeps GHSA-xxxx and its
// CVE from becoming two separate candidates.
//
// A match adds a KindPublicAdvisory claim, which is deterministic and
// top-strength, so a correlated candidate reaches CONFIRMED. That is the right
// answer — a published advisory is an authority asserting the vulnerability is
// real — and it is also why the matching rules above refuse to guess.
//
// Disclosure widens to PUBLIC on a match, since a published advisory has
// already said everything there is to withhold, except when the candidate is
// EMBARGOED: an embargo may cover a second, unpublished defect in the same
// artifact, and lifting it here would publish that one too.
func CorrelateAdvisories(c *Candidate, advs []Advisory) bool {
	if c == nil || len(advs) == 0 {
		return false
	}
	known := make(map[string]bool, len(c.Advisories))
	for _, id := range c.Advisories {
		known[strings.ToUpper(id)] = true
	}

	matched := false
	for _, a := range advs {
		if !advisoryMatches(c, a, known) {
			continue
		}
		matched = true
		for _, id := range a.identifiers() {
			if id != "" {
				known[strings.ToUpper(id)] = true
			}
		}
		c.Advisories = dedupeStrings(append(c.Advisories, a.identifiers()...))
		c.addClaim(evidence.Claim{
			Kind:      evidence.KindPublicAdvisory,
			Statement: fmt.Sprintf("advisory %s reports this weakness in %s package %s", a.ID, c.Ecosystem, c.Package),
			Provenance: evidence.Provenance{
				Source: "osv",
				// No SourceID: an advisory is an authority, not one of the
				// reporters whose independence the network counts. Letting
				// advisories increment that count would let a single record
				// look like corroboration by two environments.
				Reference:  a.ID,
				ObservedAt: a.Published,
			},
			Attributes: advisoryAttributes(a),
		})
	}
	if !matched {
		return false
	}
	if len(c.Advisories) > maxAdvisoriesKept {
		c.Advisories = c.Advisories[:maxAdvisoriesKept]
	}
	if c.Disclosure != DisclosureEmbargoed {
		c.Disclosure = DisclosurePublic
	}
	c.syncState()
	return true
}

// advisoryAttributes records the advisory facts worth keeping on the claim,
// constrained to the shapes the privacy layer already allows.
func advisoryAttributes(a Advisory) map[string]string {
	attrs := map[string]string{}
	if AdvisoryShaped(a.ID) {
		attrs["advisory"] = a.ID
	}
	if sev := strings.ToLower(strings.TrimSpace(a.Severity)); severityLabels[sev] {
		attrs["severity"] = sev
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// advisoryMatches decides whether an advisory explains a candidate.
func advisoryMatches(c *Candidate, a Advisory, known map[string]bool) bool {
	for _, id := range a.identifiers() {
		if id != "" && known[strings.ToUpper(id)] {
			return true
		}
	}
	if !strings.EqualFold(normalizeEcosystem(a.Ecosystem), c.Ecosystem) ||
		!strings.EqualFold(normalizePackage(a.Package), c.Package) {
		return false
	}
	for _, v := range rangeBounds(c.AffectedRange) {
		if a.Covers(v) {
			return true
		}
	}
	return false
}

// Dedupe collapses candidates that resolve to the same advisory for the same
// artifact, keeping the merged evidence of every candidate it absorbs.
//
// The artifact is part of the key on purpose: one CVE routinely affects several
// packages, and collapsing those into one record would report a vulnerability
// in a package the organization does not even have. Candidates with no
// advisory keep their own identity — an uncorrelated candidate has nothing to
// prove it is the same defect as its neighbour.
func Dedupe(cands []*Candidate) []*Candidate {
	if len(cands) == 0 {
		return nil
	}
	ordered := make([]*Candidate, 0, len(cands))
	for _, c := range cands {
		if c != nil {
			ordered = append(ordered, c)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	byKey := make(map[string]*Candidate, len(ordered))
	out := make([]*Candidate, 0, len(ordered))
	for _, c := range ordered {
		key := dedupeKey(c)
		if head, ok := byKey[key]; ok {
			Merge(head, c)
			continue
		}
		byKey[key] = c
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// dedupeKey is the artifact plus the candidate's lowest-sorting advisory id, or
// the fingerprint when it has none.
func dedupeKey(c *Candidate) string {
	if len(c.Advisories) == 0 {
		return "fp\x00" + c.Fingerprint
	}
	ids := dedupeStrings(c.Advisories)
	return "adv\x00" + c.Ecosystem + "\x00" + c.Package + "\x00" + strings.ToUpper(ids[0])
}

// rangeBounds extracts the concrete versions named by a range expression such
// as "1.2.3", ">=1.2.3 <=1.3.0", or "1.2.3,1.4.0". Comparison operators are
// stripped; what is left are the endpoints worth testing against an advisory.
func rangeBounds(expr string) []string {
	expr = normalizeVersion(expr)
	if expr == "" {
		return nil
	}
	fields := strings.FieldsFunc(expr, func(r rune) bool { return r == ' ' || r == ',' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimLeft(f, "<>=^~ ")
		if f != "" && f != "*" {
			out = append(out, f)
		}
	}
	return out
}

// comparableVersion reports whether v carries an ordering compareVersions can
// be trusted with. A value whose leading segment is not numeric — "latest", a
// git SHA, an empty string — does not, and nox says so instead of ordering it
// arbitrarily.
func comparableVersion(v string) bool {
	v = normalizeVersion(v)
	if v == "" {
		return false
	}
	lead, _, _ := strings.Cut(v, ".")
	lead, _, _ = strings.Cut(lead, "-")
	if lead == "" {
		return false
	}
	for _, r := range lead {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// compareVersions orders two semver-ish versions: numeric segments first, then
// prerelease, where a release outranks any prerelease of the same numbers.
func compareVersions(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)

	for i := 0; i < len(an) || i < len(bn); i++ {
		av, bv := 0, 0
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}

	switch {
	case apre == bpre:
		return 0
	case apre == "": // a release beats a prerelease of the same numbers
		return 1
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

// splitVersion breaks "1.2.3-rc1" into its numeric segments and prerelease. A
// non-numeric segment contributes 0 rather than aborting: by the time this is
// reached, comparableVersion has already vouched for the leading segment.
func splitVersion(v string) (nums []int, prerelease string) {
	v = normalizeVersion(v)
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	nums = make([]int, 0, len(parts))
	for _, part := range parts {
		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				n = 0
				break
			}
			n = n*10 + int(r-'0')
		}
		nums = append(nums, n)
	}
	return nums, pre
}
