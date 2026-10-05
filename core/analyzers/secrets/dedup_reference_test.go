package secrets

import (
	"fmt"
	"sort"

	"github.com/nox-hq/nox/core/findings"
)

// The dedup pass as it was before it became sub-quadratic (68cf661), kept
// verbatim except for names, as the oracle for TestDedupMatchesReference.
// The rewrite's contract is that its output -- survivors, their order, and
// every suppression with its survivor and reason -- is identical.
//
// The one addition is refSelfDropObserved, called where an anchor that does
// not own its token drops itself. That suppression names the owner as its
// survivor, so it cannot be told from an ordinary non-owner drop by its
// record; the coverage test counts it at its call site instead.

// refSelfDropObserved is a no-op except while the coverage test counts.
var refSelfDropObserved = func() {}

func refDedupBySpecificity(in []findings.Finding, spec map[string]int, content []byte) ([]findings.Finding, []suppression) {
	if len(in) < 2 {
		return in, nil
	}
	// Index findings so we can sort by (line, start col) without copying the
	// findings themselves (they are passed around by pointer/value per repo
	// convention; here we index to satisfy no-rangeValCopy).
	order := make([]int, len(in))
	for i := range in {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		fa, fb := &in[order[a]], &in[order[b]]
		if fa.Location.StartLine != fb.Location.StartLine {
			return fa.Location.StartLine < fb.Location.StartLine
		}
		if fa.Location.StartColumn != fb.Location.StartColumn {
			return fa.Location.StartColumn < fb.Location.StartColumn
		}
		return fa.RuleID < fb.RuleID
	})

	suppressed := make([]bool, len(in))
	// Collected in drop order, which is deterministic because `order` is.
	var dropped []suppression

	// Pass 1 — owner resolution. For each finding whose matched token names a
	// known provider, drop every OTHER provider finding overlapping its span
	// that isn't a canonical owner of that token. Generic (non-provider)
	// findings are left for pass 2.
	refResolveOwners(in, order, suppressed, spec, content, &dropped)

	for a := 0; a < len(order); a++ {
		ia := order[a]
		if suppressed[ia] {
			continue
		}
		fa := &in[ia]
		for b := a + 1; b < len(order); b++ {
			ib := order[b]
			if suppressed[ib] {
				continue
			}
			fb := &in[ib]
			if fb.Location.StartLine != fa.Location.StartLine {
				break // sorted by line; no more same-line candidates
			}
			if !spansOverlap(fa, fb) {
				continue
			}
			// Suppress only a strictly-less-specific overlapping finding. A
			// generic entropy/keyword rule loses to any provider rule on the
			// same span. Two findings of EQUAL specificity are both kept: the
			// corpus proves a single token can legitimately be owed to two
			// distinct provider rules (AWS is annotated SEC-001 AND SEC-508),
			// so provider-vs-provider is never collapsed here — that would turn
			// a required true positive into a false negative.
			sa := specificityOf(fa.RuleID, spec)
			sb := specificityOf(fb.RuleID, spec)
			switch {
			case sb > sa:
				suppressed[ia] = true
				dropped = append(dropped, specificitySuppression(fa, fb))
			case sa > sb:
				suppressed[ib] = true
				dropped = append(dropped, specificitySuppression(fb, fa))
			}
			if suppressed[ia] {
				break // fa gone; move to next anchor
			}
		}
	}

	out := make([]findings.Finding, 0, len(in))
	for i := range in {
		if !suppressed[i] {
			out = append(out, in[i])
		}
	}
	return out, dropped
}

func refResolveOwners(in []findings.Finding, order []int, suppressed []bool, spec map[string]int, content []byte, dropped *[]suppression) {
	for a := 0; a < len(order); a++ {
		ia := order[a]
		if suppressed[ia] {
			continue
		}
		fa := &in[ia]
		if specificityOf(fa.RuleID, spec) < specProviderDefault {
			continue // a generic match does not get to say who owns a token
		}
		owners := ownersForValue(matchedValue(content, fa))
		if owners == nil {
			continue // fa's token isn't a recognised provider token
		}
		// fa names a provider; drop overlapping provider findings on this span
		// that aren't canonical owners (including fa itself if, e.g., a Clerk
		// rule matched a Stripe token).
		for b := 0; b < len(order); b++ {
			ib := order[b]
			if ib == ia || suppressed[ib] {
				continue
			}
			fb := &in[ib]
			if fb.Location.StartLine != fa.Location.StartLine {
				continue
			}
			if !spansOverlap(fa, fb) {
				continue
			}
			// Only resolve among provider-tier findings; leave generic ones.
			if specificityOf(fb.RuleID, spec) < specProviderDefault {
				continue
			}
			if _, ok := owners[fb.RuleID]; ok {
				// Two JWT owners on one span report one token twice when a
				// non-compact header precedes a compact JWT: SEC-952 reads the
				// compact header as its claims and the compact claims as its
				// signature, and all three decode. SEC-952 yields to the
				// compact owner, which reports the token exactly as main does.
				// (Its span is not always the whole token: a non-compact
				// header whose JSON nests `{"` at a 3-byte boundary carries an
				// inner eyJ, and SEC-371 starts there -- main's span for that
				// input.) Once fa is dropped here it is an owner, so the
				// self-drop after this loop cannot record it a second time.
				if loser := nonCompactLoser(fa, fb); loser != nil {
					li := ia
					if loser == fb {
						li = ib
					}
					suppressed[li] = true
					*dropped = append(*dropped, suppression{
						dropped:  refTo(loser),
						survivor: refTo(otherOf(loser, fa, fb)),
						reason:   "two JWT owners overlap: the compact token is the complete JWT, and the non-compact match around it reads that token's header and claims as its own claims and signature, so the token is reported once, by its compact owner",
					})
					if li == ia {
						break
					}
				}
				continue
			}
			// A non-owner is dropped only when its VALUE is the token: a
			// name-bound rule (KEY=<token>, Authorization: Bearer <token>)
			// claims the same secret twice. One that merely overlaps it, such
			// as a database URL whose password precedes a token in its query,
			// claims something else, and dropping it lost that credential.
			if !valueWithin(content, fb, fa) {
				continue
			}
			suppressed[ib] = true
			*dropped = append(*dropped, refOwnerSuppression(in, order, suppressed, fa, fb, owners))
		}
		// If fa itself is not an owner of the token it matched (a mis-attributed
		// provider rule, e.g. Clerk firing on a Stripe key), drop it too — but
		// only once at least one true owner is present on the span, so we never
		// suppress the last finding on a real secret.
		if _, ok := owners[fa.RuleID]; !ok && refOwnerPresent(in, order, suppressed, fa, owners) {
			suppressed[ia] = true
			*dropped = append(*dropped, refOwnerSuppression(in, order, suppressed, fa, fa, owners))
			refSelfDropObserved()
		}
	}
}

func refOwnerPresent(in []findings.Finding, order []int, suppressed []bool, fa *findings.Finding, owners map[string]struct{}) bool {
	for _, idx := range order {
		if suppressed[idx] {
			continue
		}
		fb := &in[idx]
		if fb.Location.StartLine != fa.Location.StartLine || !spansOverlap(fa, fb) {
			continue
		}
		if _, ok := owners[fb.RuleID]; ok {
			return true
		}
	}
	return false
}

func refOwnerSuppression(in []findings.Finding, order []int, suppressed []bool, anchor, dropped *findings.Finding, owners map[string]struct{}) suppression {
	survivor := anchor
	if idx, ok := refOwnerIndex(in, order, suppressed, anchor, owners); ok {
		survivor = &in[idx]
	}
	return suppression{
		dropped:  refTo(dropped),
		survivor: refTo(survivor),
		reason: fmt.Sprintf(
			"the matched token's prefix names a provider whose canonical rule is %s; %s matched the same span without owning that token type",
			survivor.RuleID, dropped.RuleID),
	}
}

func refOwnerIndex(in []findings.Finding, order []int, suppressed []bool, fa *findings.Finding, owners map[string]struct{}) (int, bool) {
	for _, idx := range order {
		if suppressed[idx] {
			continue
		}
		fb := &in[idx]
		if fb.Location.StartLine != fa.Location.StartLine || !spansOverlap(fa, fb) {
			continue
		}
		if _, ok := owners[fb.RuleID]; ok {
			return idx, true
		}
	}
	return 0, false
}
