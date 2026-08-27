package vulnsource

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/degrade"
)

// VerifyingSource answers from one source while checking it against another.
//
// Replacing a neutral public database with a richer source trades a known trust
// root for a new one, and introduces a threat the public database does not
// have. Poisoning by addition — an invented vulnerability — is noisy and
// eventually noticed. Denial by omission is silent: a source that withholds a
// real CVE produces a clean scan, and nothing downstream can distinguish "no
// vulnerability" from "not told about the vulnerability".
//
// So the superset claim is checked on every lookup rather than trusted. The
// intelligence source answers; the reference source is asked the same question;
// the difference is classified:
//
//   - the reference has a record the intelligence source did not return —
//     SUPPRESSION. Reported loudly, and the record is still returned, so a
//     failing source degrades trust without ever costing a finding.
//   - the intelligence source has records the reference does not — the added
//     value, carried through with its own status.
//   - the reference could not be reached — the property was not checked, which
//     is reported as such rather than passing for a clean verification.
//
// The zero value is not usable; construct with NewVerifying.
type VerifyingSource struct {
	intel     Source
	reference Source

	// refDeg collects the reference source's own degradations, kept separate
	// from the scan's collector on purpose. When the reference fails, the
	// intelligence source may have answered perfectly — the honest impact is
	// "the superset property was not verified", not the reference's own "these
	// vulnerabilities are under-reported", which would be false and alarming.
	refDeg *degrade.Degradations

	deg *degrade.Degradations

	mu     sync.Mutex
	result Verification
}

// Discrepancy is one record the two sources disagreed about.
type Discrepancy struct {
	Query  Query
	VulnID string
	Status Status
}

// Verification is the outcome of comparing the two sources.
type Verification struct {
	// Suppressed lists records the reference published and the intelligence
	// source did not return. Any entry means the superset property failed.
	Suppressed []Discrepancy

	// Added lists records only the intelligence source returned — what the
	// richer source is actually buying.
	Added []Discrepancy

	// Checked reports whether the comparison happened at all. False means the
	// reference could not be reached, and neither list means anything.
	Checked bool
}

// Holds reports whether the superset property held on a comparison that
// actually ran. An unchecked verification does not hold — absence of a detected
// suppression is not evidence of none.
func (v Verification) Holds() bool { return v.Checked && len(v.Suppressed) == 0 }

// SuppressionRate is the share of reference records the intelligence source
// failed to return, in [0,1]. It is the metric a deployment gates on: a build
// that starts dropping advisories fails its own rollout.
//
// An unchecked verification rates 1 — the worst value — because a rollout must
// not be promoted on a check that never ran.
func (v Verification) SuppressionRate() float64 {
	if !v.Checked {
		return 1
	}
	total := len(v.Suppressed) + len(v.Added)
	if total == 0 {
		return 0
	}
	return float64(len(v.Suppressed)) / float64(total)
}

// NewVerifying returns a Source that answers from intel and checks it against a
// reference built by newReference.
//
// The reference is built rather than passed so the VerifyingSource owns its
// degradation collector, which is what lets it tell "the reference disagreed"
// from "the reference never answered". deg may be nil.
func NewVerifying(intel Source, newReference func(*degrade.Degradations) Source, deg *degrade.Degradations) *VerifyingSource {
	refDeg := &degrade.Degradations{}
	return &VerifyingSource{
		intel:     intel,
		reference: newReference(refDeg),
		refDeg:    refDeg,
		deg:       deg,
	}
}

// Name identifies the source being verified, not the verifier — the records
// come from the intelligence source, and provenance should say so.
func (v *VerifyingSource) Name() string { return v.intel.Name() }

// Verification returns the outcome of the most recent Lookup.
func (v *VerifyingSource) Verification() Verification {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.result
}

// Lookup queries both sources and returns the intelligence source's records,
// with any record the reference published but the intelligence source withheld
// added back.
//
// Filling the gap is deliberate. The alternative — return what the intelligence
// source said and merely complain — makes a compromised or broken source able
// to hide vulnerabilities from a scan that the operator was told is a superset.
// A discrepancy must cost trust, never coverage.
func (v *VerifyingSource) Lookup(ctx context.Context, qs []Query) (map[int][]Record, error) {
	var (
		intelOut, refOut map[int][]Record
		intelErr, refErr error
		wg               sync.WaitGroup
	)

	wg.Add(2)
	go func() { defer wg.Done(); intelOut, intelErr = v.intel.Lookup(ctx, qs) }()
	go func() { defer wg.Done(); refOut, refErr = v.reference.Lookup(ctx, qs) }()
	wg.Wait()

	// An intelligence source that cannot answer at all is a hard failure: there
	// is nothing to verify and nothing to report.
	if intelErr != nil {
		return nil, intelErr
	}
	if intelOut == nil {
		intelOut = make(map[int][]Record)
	}

	// The reference is the checker, not the answerer. It failing means the
	// check did not happen — which must be said, not assumed away.
	if refErr != nil || v.refDeg.Len() > 0 {
		detail := "reference source unavailable"
		if refErr != nil {
			detail = fmt.Sprintf("reference source failed: %v", refErr)
		} else if items := v.refDeg.Items(); len(items) > 0 {
			detail = fmt.Sprintf("reference source degraded: %s", items[0].Detail)
		}
		v.deg.Add(degrade.IntelUnverified, detail,
			fmt.Sprintf("the %s source answered but was not checked against a reference; "+
				"this scan cannot confirm it withheld nothing", v.intel.Name()))
		v.setResult(Verification{Checked: false})
		return intelOut, nil
	}

	result := Verification{Checked: true}
	for i, q := range qs {
		have := idSet(intelOut[i])
		for _, ref := range refOut[i] {
			if _, ok := have[ref.ID]; ok {
				continue
			}
			result.Suppressed = append(result.Suppressed, Discrepancy{
				Query: q, VulnID: ref.ID, Status: StatusPublished,
			})
			// Return it anyway: a discrepancy costs trust, not coverage.
			intelOut[i] = append(intelOut[i], ref)
		}

		refHave := idSet(refOut[i])
		for _, rec := range intelOut[i] {
			if _, ok := refHave[rec.ID]; ok {
				continue
			}
			result.Added = append(result.Added, Discrepancy{
				Query: q, VulnID: rec.ID, Status: rec.Status(),
			})
		}
	}

	sortDiscrepancies(result.Suppressed)
	sortDiscrepancies(result.Added)

	if len(result.Suppressed) > 0 {
		v.deg.Add(degrade.IntelSuppression,
			fmt.Sprintf("%s withheld %d record(s) published by %s: %s",
				v.intel.Name(), len(result.Suppressed), v.reference.Name(),
				strings.Join(vulnIDs(result.Suppressed), ", ")),
			"the vulnerability source is not a superset of its reference; "+
				"the withheld records were restored from the reference for this scan, "+
				"but the source cannot be trusted to report completely")
	}

	v.setResult(result)
	return intelOut, nil
}

func (v *VerifyingSource) setResult(r Verification) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.result = r
}

func idSet(recs []Record) map[string]struct{} {
	out := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		out[r.ID] = struct{}{}
	}
	return out
}

func vulnIDs(ds []Discrepancy) []string {
	out := make([]string, 0, len(ds))
	seen := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		if _, ok := seen[d.VulnID]; ok {
			continue
		}
		seen[d.VulnID] = struct{}{}
		out = append(out, d.VulnID)
	}
	return out
}

// sortDiscrepancies imposes a total order so a verification reads the same on
// every run — the same reason scan output is sorted.
func sortDiscrepancies(ds []Discrepancy) {
	sort.Slice(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if a.Query.Ecosystem != b.Query.Ecosystem {
			return a.Query.Ecosystem < b.Query.Ecosystem
		}
		if a.Query.Name != b.Query.Name {
			return a.Query.Name < b.Query.Name
		}
		if a.Query.Version != b.Query.Version {
			return a.Query.Version < b.Query.Version
		}
		return a.VulnID < b.VulnID
	})
}
