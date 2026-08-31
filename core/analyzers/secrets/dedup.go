package secrets

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
)

// This file implements rule-specificity deduplication for secret findings. A
// single hard-coded provider token (a GitHub PAT, a Slack bot token, a Stripe
// key) matches its provider-specific rule AND a stack of generic
// high-entropy/keyword rules that all fire on the same span. Per-rule scoring
// sees each of those as a legitimate hit, but a human sees ONE issue inflated
// 5-8x. gitleaks/trufflehog collapse such overlaps to the most-specific match;
// we do the same. When several findings overlap on the same line, we keep the
// single highest-specificity finding and suppress the rest.

// ruleSpecificity ranks a rule ID from most to least specific. A higher score
// wins when findings overlap. Provider-specific rules (a distinctive prefix or
// vendor pattern) are the ground truth for a token; generic entropy/keyword
// rules are the noise the density metric is built to expose.
//
// The ranking is derived structurally from the rule set at construction time
// (see specificityByRule) rather than hard-coded per ID, so newly added
// provider rules rank correctly without a code change here. This function is
// the fallback for a rule ID not present in that map.
func ruleSpecificityFallback(ruleID string) int {
	switch ruleID {
	// Generic entropy rules are the least specific — always losers.
	case "SEC-161", "SEC-162", "SEC-163":
		return specGenericEntropy
	default:
		return specProviderDefault
	}
}

// Specificity tiers. Larger is more specific (wins a span contest).
const (
	specGenericEntropy  = 0 // SEC-161/162/163 high-entropy heuristics
	specKeywordGeneric  = 1 // loose vendor patterns gated by a secret_shape post-filter
	specProviderDefault = 2 // an anchored provider regex (all providers share this tier)
)

// specificityByRule builds a rule-ID → specificity-tier map from the analyzer's
// rule set. It classifies each secret rule by structure:
//   - entropy matcher                       → generic entropy (lowest)
//   - regex with a secret_shape post-filter → keyword-generic (loose vendor
//     patterns like `\b[a-z0-9]{32}\b` that only survive via entropy shape)
//   - any other (anchored provider) regex   → provider (all providers share
//     one tier; provider-vs-provider ties are resolved by owner resolution, not
//     by specificity — see dedupBySpecificity).
//
// Doing this structurally (not by an ID allowlist) keeps the ranking correct as
// the ~700-rule provider table grows.
func specificityByRule(rs []*rules.Rule) map[string]int {
	out := make(map[string]int, len(rs))
	for _, r := range rs {
		out[r.ID] = classifyRuleSpecificity(r)
	}
	return out
}

// classifyRuleSpecificity assigns a specificity tier to a single rule by shape.
func classifyRuleSpecificity(r *rules.Rule) int {
	if r.MatcherType == "entropy" {
		return specGenericEntropy
	}
	if r.Metadata != nil && r.Metadata["secret_shape"] == "true" {
		// Loose vendor patterns (e.g. `\b[a-z0-9]{32}\b`) gated only by an
		// entropy/shape post-filter: more specific than raw entropy but they
		// still match many unrelated 32-char blobs, so they lose to an
		// anchored provider regex on the same span.
		return specKeywordGeneric
	}
	// Every anchored provider regex is one tier. We deliberately do NOT rank
	// provider rules against each other by prefix length: a canonical rule may
	// use a char-class prefix (SEC-003 `gh[pso]_…`) while its Gitleaks-imported
	// alias uses a longer literal (SEC-216 `ghp_…`), so a length-based ranking
	// would suppress the canonical rule in favour of the alias — turning a
	// required true positive into a false negative. Provider-vs-provider ties
	// are resolved by resolveOwners (below), not by specificity.
	return specProviderDefault
}

// dedupBySpecificity collapses secret findings that overlap on the same line to
// the canonical finding(s) per overlapping span. It runs two passes over each
// overlapping span:
//
//  1. Owner resolution: if the matched token starts with a recognised provider
//     prefix (ghp_, xoxb-, sk_live_, AKIA, …), keep only that provider's
//     canonical owner rule(s) and drop every other provider finding on the span.
//     This resolves the multiple-provider-rules-per-token pileup (the dominant
//     precision drag) while preserving co-canonical pairs like AWS SEC-001/508.
//  2. Specificity collapse: any generic entropy/keyword-shape finding that
//     overlaps a surviving provider finding is dropped.
//
// Findings on different lines, or non-overlapping spans on the same line, are
// all preserved. content is the file bytes, used to recover the matched token
// for owner resolution; spec maps rule ID → specificity tier.
func dedupBySpecificity(in []findings.Finding, spec map[string]int, content []byte) []findings.Finding {
	if len(in) < 2 {
		return in
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

	// Pass 1 — owner resolution. For each finding whose matched token names a
	// known provider, drop every OTHER provider finding overlapping its span
	// that isn't a canonical owner of that token. Generic (non-provider)
	// findings are left for pass 2.
	resolveOwners(in, order, suppressed, spec, content)

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
			case sa > sb:
				suppressed[ib] = true
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
	return out
}

// resolveOwners implements pass 1 of dedupBySpecificity. For every finding
// whose matched token names a known provider (by prefix), it suppresses all
// OTHER provider findings on the same overlapping span that are not canonical
// owners of that token. Generic entropy/keyword findings are untouched here —
// they are handled by the specificity collapse in pass 2. order is the
// (line,col,rule) sort; suppressed is updated in place.
func resolveOwners(in []findings.Finding, order []int, suppressed []bool, spec map[string]int, content []byte) {
	for a := 0; a < len(order); a++ {
		ia := order[a]
		if suppressed[ia] {
			continue
		}
		fa := &in[ia]
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
			if _, ok := owners[fb.RuleID]; !ok {
				suppressed[ib] = true
			}
		}
		// If fa itself is not an owner of the token it matched (a mis-attributed
		// provider rule, e.g. Clerk firing on a Stripe key), drop it too — but
		// only once at least one true owner is present on the span, so we never
		// suppress the last finding on a real secret.
		if _, ok := owners[fa.RuleID]; !ok && ownerPresent(in, order, suppressed, fa, owners) {
			suppressed[ia] = true
		}
	}
}

// ownerPresent reports whether some non-suppressed finding overlapping fa's
// span is a canonical owner in owners.
func ownerPresent(in []findings.Finding, order []int, suppressed []bool, fa *findings.Finding, owners map[string]struct{}) bool {
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

// matchedValue recovers the matched token text for a finding from the file
// content using its byte offsets. Returns "" if the offsets are unusable.
func matchedValue(content []byte, f *findings.Finding) string {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start || end > len(content) {
		return ""
	}
	return string(content[start:end])
}

// canonicalOwner maps a provider token prefix to the rule ID(s) that are the
// authoritative owner of that token shape. When several provider rules match
// the SAME token span, only the owner rule(s) are kept and the redundant
// aliases (typically Gitleaks-imported duplicates that fire on the same prefix)
// are dropped. This encodes the one-rule-per-secret-type discipline that
// gitleaks/trufflehog enforce by construction; nox accumulated multiple rules
// per token over successive imports, so we resolve the winner here.
//
// The prefix is matched case-sensitively against the matched value (leading
// characters). A provider with two co-canonical rules (AWS: the primary
// SEC-001 plus the recognised alternate SEC-508) lists both — they are both
// kept, never collapsed against each other.
type ownerEntry struct {
	prefix string
	owners map[string]struct{}
}

func owned(ids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

// canonicalOwners is ordered longest-prefix-first so `sk_live_` is tested
// before a hypothetical `sk_`. Prefixes are the distinctive literal lead of
// each provider token.
var canonicalOwners = []ownerEntry{
	{"AKIA", owned("SEC-001", "SEC-508")}, // AWS access key id (+ alternate)
	{"ghp_", owned("SEC-003")},            // GitHub PAT
	{"gho_", owned("SEC-003")},            // GitHub OAuth
	{"ghs_", owned("SEC-003")},            // GitHub server-to-server
	{"ghu_", owned("SEC-017")},            // GitHub user-to-server
	{"xoxb-", owned("SEC-023")},           // Slack bot token
	{"xoxp-", owned("SEC-024")},           // Slack user token
	{"sk_live_", owned("SEC-030")},        // Stripe live secret key
	{"sk_test_", owned("SEC-030")},        // Stripe test secret key
	{"AIza", owned("SEC-007")},            // GCP / Gemini API key
	{"glpat-", owned("SEC-018")},          // GitLab PAT
	// A JWT is three base64url segments starting with eyJ (`{"` encoded), and
	// three rules match it — SEC-084, SEC-251, SEC-371. They are one credential
	// class, so they collapse to one canonical owner the way the provider
	// prefixes above do. SEC-371 is canonical: the tightest pattern, at high
	// severity. This became reachable only once LooksLikeJWT stopped the
	// data-blob refiner dropping real JWTs — before that, all three were
	// suppressed upstream and never reached dedup.
	{"eyJ", owned("SEC-371")}, // JSON Web Token
}

// ownersForValue returns the owner rule-ID set for a matched value, or nil if
// the value doesn't start with a recognised provider prefix (in which case no
// alias resolution applies and all overlapping provider findings are kept).
func ownersForValue(value string) map[string]struct{} {
	v := strings.TrimLeft(value, `"'`)
	for i := range canonicalOwners {
		if strings.HasPrefix(v, canonicalOwners[i].prefix) {
			return canonicalOwners[i].owners
		}
	}
	return nil
}

// isBareProviderPrefix reports whether a finding matched only a provider prefix
// (e.g. `glpat-`, `sk_live_`) with no credential body following it — the shape a
// pattern-vocabulary file has when it names the prefixes its rules detect
// (`{"glpat-", ...}`, `// prefix (ghp_, xoxb-, sk_live_, ...)`). A live token
// always carries a 20+ char high-entropy body; a match that is the bare prefix,
// immediately followed by a non-token-body byte, is a reference, not a secret.
//
// This runs AFTER dedupBySpecificity, so on a real token the precise owner rule
// (which requires the body) has already claimed the span and the bare-prefix
// alias is gone — a surviving bare-prefix match therefore never coincides with a
// real credential.
func isBareProviderPrefix(content []byte, f *findings.Finding) bool {
	value := matchedValue(content, f)
	v := strings.TrimLeft(value, `"'`)
	if v == "" {
		return false
	}
	prefix, ok := recognisedProviderPrefix(v)
	if !ok {
		return false
	}
	// The match must be ONLY the prefix (no body captured in the span).
	if v != prefix {
		return false
	}
	// Inspect the source bytes immediately after the match: if a token body of
	// credential-length characters follows, this is a real (unquoted) token and
	// must be kept. A boundary (quote, comma, brace, space, end of line) means
	// the prefix stands alone as vocabulary.
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	return !tokenBodyFollows(content, end)
}

// recognisedProviderPrefix returns the longest canonicalOwners prefix that v
// starts with, or ("", false) if none matches.
func recognisedProviderPrefix(v string) (string, bool) {
	for i := range canonicalOwners {
		if strings.HasPrefix(v, canonicalOwners[i].prefix) {
			return canonicalOwners[i].prefix, true
		}
	}
	return "", false
}

// barePrefixBodyThreshold is the run length of token-body characters that, if
// present immediately after a provider prefix, marks a real credential rather
// than a bare-prefix reference. Provider tokens carry 20+ body chars.
const barePrefixBodyThreshold = 20

// tokenBodyFollows reports whether content at offset begins a run of at least
// barePrefixBodyThreshold token-body characters (alphanumerics plus `-`/`_`,
// the alphabet real provider tokens draw from).
func tokenBodyFollows(content []byte, offset int) bool {
	run := 0
	for i := offset; i < len(content) && run < barePrefixBodyThreshold; i++ {
		if !isTokenBodyByte(content[i]) {
			break
		}
		run++
	}
	return run >= barePrefixBodyThreshold
}

// isTokenBodyByte reports whether c can appear in a provider-token body.
func isTokenBodyByte(c byte) bool {
	return c == '-' || c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// specificityOf returns the specificity tier for a rule ID.
func specificityOf(ruleID string, spec map[string]int) int {
	if s, ok := spec[ruleID]; ok {
		return s
	}
	return ruleSpecificityFallback(ruleID)
}

// spansOverlap reports whether two findings on the same line cover overlapping
// column ranges. Two findings that touch the same token (share any column) are
// considered the same issue for dedup purposes.
func spansOverlap(a, b *findings.Finding) bool {
	as, ae := a.Location.StartColumn, a.Location.EndColumn
	bs, be := b.Location.StartColumn, b.Location.EndColumn
	if ae == 0 {
		ae = as
	}
	if be == 0 {
		be = bs
	}
	return as <= be && bs <= ae
}
