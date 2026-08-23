package intel

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/evidence"
)

// Aggregate clusters observations into candidates.
//
// Observations that do not validate are dropped rather than clustered. An
// observation nox cannot fully account for might carry content, and a cluster
// built from one would carry it onward into a stored candidate.
//
// Clustering uses the recomputed fingerprint, never the one on the incoming
// observation: on the ingest side that field is attacker-controlled, and
// honouring it would let a hostile reporter merge unrelated candidates —
// attaching their own claims to someone else's package.
//
// The ledger holds ONE claim per (kind, reporter) pair, not one per
// observation. A thousand reports from one CI job are one reporter's opinion,
// stated a thousand times, and materialising them as a thousand claims would
// make the ledger's size look like evidence. The raw count is preserved
// separately in ObservationCount and in the claim's "observations" attribute.
//
// When two or more independent reporters agree, Aggregate adds a single
// KindIndependentObservation claim. That is where corroboration earns its
// weight — from distinct sources agreeing, never from repetition.
//
// now is an RFC3339 timestamp used only as a fallback for observations whose
// window cannot be derived; the package never reads a clock.
func Aggregate(obs []Observation, now string) []*Candidate {
	groups := make(map[string][]Observation)
	for _, o := range obs {
		if err := o.Validate(); err != nil {
			continue
		}
		fp := Fingerprint(o)
		groups[fp] = append(groups[fp], o)
	}

	fps := make([]string, 0, len(groups))
	for fp := range groups {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	out := make([]*Candidate, 0, len(fps))
	for _, fp := range fps {
		out = append(out, buildCandidate(fp, groups[fp], now))
	}
	return out
}

// buildCandidate turns one fingerprint group into a candidate.
func buildCandidate(fp string, group []Observation, now string) *Candidate {
	// A stable input order makes every derived string reproducible regardless
	// of the order the caller happened to collect observations in.
	sorted := make([]Observation, len(group))
	copy(sorted, group)
	sort.Slice(sorted, func(i, j int) bool { return observationLess(sorted[i], sorted[j]) })

	first := sorted[0]
	c := &Candidate{
		ID:               NewCandidateID(fp),
		Fingerprint:      fp,
		Ecosystem:        normalizeEcosystem(first.Ecosystem),
		Package:          normalizePackage(first.Package),
		WeaknessClass:    first.WeaknessClass,
		State:            StateObserved,
		Disclosure:       DisclosureInternal,
		ObservationCount: len(sorted),
	}

	versions := make([]string, 0, len(sorted))
	stamps := make([]string, 0, len(sorted))
	for _, o := range sorted {
		if v := normalizeVersion(o.Version); v != "" {
			versions = append(versions, v)
		}
		stamps = append(stamps, o.ObservedAt)
	}
	c.AffectedRange = versionSpan(versions)
	c.FirstObserved, c.LastObserved = observationWindow(stamps, now)
	c.Summary = summarize(c)

	for _, cl := range collapseClaims(sorted) {
		c.addClaim(cl)
	}
	if n := c.IndependentSources(); n >= 2 {
		c.addClaim(evidence.Claim{
			Kind:      evidence.KindIndependentObservation,
			Statement: fmt.Sprintf("%d independent sources reported this weakness in the same artifact", n),
			Provenance: evidence.Provenance{
				Source: "nox-intel",
				// No SourceID: this claim is nox's own reading of the other
				// claims, and counting it as a reporter would let the network
				// corroborate itself.
				ObservedAt: c.LastObserved,
			},
			Attributes: map[string]string{"independent_sources": strconv.Itoa(n)},
		})
	}
	c.syncState()
	return c
}

// collapseClaims produces one claim per (kind, reporter) pair, in deterministic
// order.
func collapseClaims(sorted []Observation) []evidence.Claim {
	type agg struct {
		kind     evidence.Kind
		obs      Observation
		count    int
		earliest string
	}
	keys := make([]string, 0, len(sorted))
	byKey := make(map[string]*agg, len(sorted))
	for _, o := range sorted {
		key := string(o.Kind) + "\x00" + o.Provenance.SourceID
		a, ok := byKey[key]
		if !ok {
			byKey[key] = &agg{kind: o.Kind, obs: o, count: 1, earliest: o.ObservedAt}
			keys = append(keys, key)
			continue
		}
		a.count++
		if earlier(o.ObservedAt, a.earliest) {
			a.earliest = o.ObservedAt
		}
	}
	sort.Strings(keys)

	claims := make([]evidence.Claim, 0, len(keys))
	for _, k := range keys {
		a := byKey[k]
		p := a.obs.Provenance
		p.ObservedAt = a.earliest
		attrs := map[string]string{"observations": strconv.Itoa(a.count)}
		if a.obs.RuleID != "" {
			attrs["rule_id"] = a.obs.RuleID
		}
		claims = append(claims, evidence.Claim{
			Kind: a.kind,
			Statement: fmt.Sprintf("%s reported %s in %s package %s",
				sourceLabel(p), a.obs.WeaknessClass, normalizeEcosystem(a.obs.Ecosystem), normalizePackage(a.obs.Package)),
			Provenance: p,
			Attributes: attrs,
		})
	}
	return claims
}

// sourceLabel names the reporter in a claim statement without identifying it.
func sourceLabel(p evidence.Provenance) string {
	if p.SourceID == "" {
		return "an unattributed source"
	}
	// Eight hex digits are enough to tell two reporters apart in a report and
	// carry no more information than the opaque id already did.
	return "source " + p.SourceID[:8]
}

// observationLess gives observations a total, content-independent order.
func observationLess(a, b Observation) bool {
	if a.ObservedAt != b.ObservedAt {
		return a.ObservedAt < b.ObservedAt
	}
	if a.Provenance.SourceID != b.Provenance.SourceID {
		return a.Provenance.SourceID < b.Provenance.SourceID
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Version < b.Version
}

// versionSpan renders the version coverage of a cluster: a single version when
// every observation agrees, otherwise a closed range across the extremes.
// Versions nox cannot order are listed verbatim rather than guessed at.
func versionSpan(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	uniq := dedupeStrings(versions)
	if len(uniq) == 1 {
		return uniq[0]
	}
	lo, hi := "", ""
	for _, v := range uniq {
		if !comparableVersion(v) {
			continue
		}
		if lo == "" || compareVersions(v, lo) < 0 {
			lo = v
		}
		if hi == "" || compareVersions(v, hi) > 0 {
			hi = v
		}
	}
	if lo == "" || hi == "" || lo == hi {
		// Nothing orderable: state the versions rather than inventing a span.
		return strings.Join(uniq, ",")
	}
	return ">=" + lo + " <=" + hi
}

// observationWindow returns the earliest and latest timestamps, falling back to
// now when a cluster has none that parse.
func observationWindow(stamps []string, now string) (first, last string) {
	for _, s := range stamps {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			continue
		}
		if first == "" || earlier(s, first) {
			first = s
		}
		if last == "" || earlier(last, s) {
			last = s
		}
	}
	if first == "" {
		first, last = now, now
	}
	return first, last
}

// earlier reports whether RFC3339 timestamp a precedes b, breaking ties
// lexicographically so equal instants written differently still order stably.
func earlier(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	if errA != nil || errB != nil {
		return a < b
	}
	if ta.Equal(tb) {
		return a < b
	}
	return ta.Before(tb)
}

// summarize builds the candidate's one-line description from its own
// coordinates. It never copies a finding message: a message can quote the
// source line that matched, and a summary is exactly the field a human would
// paste into a public ticket.
func summarize(c *Candidate) string {
	s := fmt.Sprintf("%s in %s package %s", c.WeaknessClass, c.Ecosystem, c.Package)
	if c.AffectedRange != "" {
		s += " (" + c.AffectedRange + ")"
	}
	if len(s) > maxSummaryLen {
		s = s[:maxSummaryLen]
	}
	return s
}

// Merge folds src into dst: the union of their evidence, the union of their
// advisories, and the widest observation window.
//
// Two rules are not symmetric with the rest, and both are deliberate. The
// merged disclosure is the MORE restrictive of the two, because a merge must
// never be a way to publish an embargoed candidate by pairing it with a public
// one. The merged state is the higher of the two, except that DISMISSED never
// outranks live evidence.
func Merge(dst, src *Candidate) {
	if dst == nil || src == nil || dst == src {
		return
	}
	for _, cl := range src.Ledger.Claims {
		dst.addClaim(cl)
	}
	dst.Advisories = dedupeStrings(append(append([]string{}, dst.Advisories...), src.Advisories...))
	if len(dst.Advisories) > maxAdvisoriesKept {
		dst.Advisories = dst.Advisories[:maxAdvisoriesKept]
	}
	dst.ObservationCount += src.ObservationCount

	if dst.FirstObserved == "" || (src.FirstObserved != "" && earlier(src.FirstObserved, dst.FirstObserved)) {
		dst.FirstObserved = src.FirstObserved
	}
	if dst.LastObserved == "" || (src.LastObserved != "" && earlier(dst.LastObserved, src.LastObserved)) {
		dst.LastObserved = src.LastObserved
	}

	dst.AffectedRange = widenRange(dst.AffectedRange, src.AffectedRange)
	if dst.Ecosystem == "" {
		dst.Ecosystem = src.Ecosystem
	}
	if dst.Package == "" {
		dst.Package = src.Package
	}
	if dst.WeaknessClass == "" {
		dst.WeaknessClass = src.WeaknessClass
	}
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
	if src.State.stateRank() > dst.State.stateRank() {
		dst.State = src.State
	}
	if src.Disclosure.restrictiveness() > dst.Disclosure.restrictiveness() {
		dst.Disclosure = src.Disclosure
	}
	dst.syncState()
}

// widenRange returns a range covering both inputs. Widening only: a merge that
// narrowed the affected range would drop a version somebody actually observed.
func widenRange(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case a == b:
		return a
	}
	bounds := append(rangeBounds(a), rangeBounds(b)...)
	return versionSpan(bounds)
}

// dedupeStrings returns the sorted unique non-empty values.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
