package intel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/evidence"
)

// Shape validators. Every value that survives redaction must match one of
// these, so the redactor's guarantee is structural rather than a list of
// patterns it hopes to have thought of. Note what the character classes exclude
// everywhere: whitespace, quotes, braces, backslashes, and control characters —
// which is what prose, JSON fragments, and file contents are made of.
var (
	// slugPattern accepts lowercase identifiers: weakness classes, ecosystems,
	// analyzer names, capability names.
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// tokenPattern accepts short mixed-case identifiers: severity labels, CWE
	// ids, tool versions.
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$`)
	// packagePattern accepts a package identifier. Slashes are permitted
	// because Go module paths and npm scopes need them; a leading slash, a
	// drive letter, a backslash, "..", "~", or whitespace are not, which is
	// what separates "github.com/foo/bar" from "/Users/alice/secret/app.py".
	packagePattern = regexp.MustCompile(`^[@A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$`)
	// versionPattern accepts a concrete version or a simple range expression.
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9<>=^~*][A-Za-z0-9.,<>=^~*+ -]{0,63}$`)
	// ruleIDPattern accepts a nox rule identifier such as "SECRETS-001".
	ruleIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)
	// advisoryPattern accepts the advisory identifiers nox correlates against.
	// It is an allowlist of issuing authorities, not a general id pattern: a
	// reference that is not an advisory is not a citation anyone can check, and
	// an unconstrained reference field is a free-text field by another name.
	advisoryPattern = regexp.MustCompile(`^(CVE|GHSA|GO|OSV|PYSEC|RUSTSEC|GMS|MAL|SNYK|DSA|USN|RHSA|ALSA|NOX-CANDIDATE)-[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`)
	// pathishPattern catches anything that reads as a filesystem or URL
	// location. It is a backstop behind the allowlists, not the primary guard.
	pathishPattern = regexp.MustCompile(`(^[/~])|(^[A-Za-z]:[\\/])|(\.\.)|(\\)|(://)`)
)

func isSlug(s string) bool        { return slugPattern.MatchString(s) }
func isToken(s string) bool       { return tokenPattern.MatchString(s) }
func isRuleID(s string) bool      { return ruleIDPattern.MatchString(s) }
func isVersionExpr(s string) bool { return versionPattern.MatchString(s) }
func isEcosystem(s string) bool   { return isSlug(strings.ToLower(strings.TrimSpace(s))) }

// isPackageName reports whether s is a package identifier rather than a
// location. Both tests must pass: matching the package shape is not enough,
// because "..%2f" style values match plausible characters while denoting a
// path.
func isPackageName(s string) bool {
	return packagePattern.MatchString(s) && !pathishPattern.MatchString(s)
}

// AdvisoryShaped reports whether s looks like an advisory identifier issued by
// a recognised authority (CVE, GHSA, GO, OSV, ...). It is exported because the
// same question is asked when deciding whether a reference may be contributed
// and when correlating advisories.
func AdvisoryShaped(s string) bool { return advisoryPattern.MatchString(strings.TrimSpace(s)) }

// attrShape names the value shape an allowlisted attribute key may carry.
type attrShape int

const (
	shapeBool attrShape = iota
	shapeSlug
	shapeToken
	shapeSeverity
	shapeConfidence
	shapeAdvisory
)

// externalAttributes is the exhaustive allowlist of attribute keys that may be
// contributed, together with the shape each key's value must have.
//
// The pairing matters as much as the list. A key allowlist on its own is
// defeated by putting a secret in an allowlisted key, so a value that does not
// match its key's declared shape is dropped exactly like an unknown key.
var externalAttributes = map[string]attrShape{
	"advisory":          shapeAdvisory,
	"analyzer":          shapeSlug,
	"capability":        shapeSlug,
	"confidence":        shapeConfidence,
	"cwe":               shapeToken,
	"direct_dependency": shapeBool,
	"fix_available":     shapeBool,
	"manifest_kind":     shapeSlug,
	"owasp":             shapeToken,
	"reachable":         shapeBool,
	"rule_version":      shapeToken,
	"runtime":           shapeSlug,
	"severity":          shapeSeverity,
	"transitive":        shapeBool,
	"weakness_subtype":  shapeSlug,
}

// orgPrivateAttributes are additionally retained in ModeOrgPrivate. They name
// where in the organization something was seen, which is what makes an internal
// exposure actionable — and is exactly what must never cross the organization
// boundary, so they are absent from every external mode.
var orgPrivateAttributes = map[string]attrShape{
	"component_id": shapeToken,
	"environment":  shapeSlug,
	"owner_team":   shapeSlug,
	"service":      shapeSlug,
}

// severityLabels and confidenceLabels are closed vocabularies. Constraining
// them to enumerations rather than a shape means these keys cannot carry
// anything at all beyond the label they exist for.
var severityLabels = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
	"info": true, "none": true, "unknown": true,
}

var confidenceLabels = map[string]bool{
	"low": true, "medium": true, "high": true, "confirmed": true,
}

// AllowedAttributeKeys returns the exhaustive, sorted allowlist of attribute
// keys that may be contributed. Anything else is dropped by Redact.
//
// It is exported so the list can be shown to a user who wants to know exactly
// what nox would send before turning contribution on. "Trust us, we filter it"
// is not an answer; the enumerable list is.
func AllowedAttributeKeys() []string {
	out := make([]string, 0, len(externalAttributes))
	for k := range externalAttributes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// OrgPrivateAttributeKeys returns the sorted additional keys retained in
// ModeOrgPrivate. They are never contributed externally.
func OrgPrivateAttributeKeys() []string {
	out := make([]string, 0, len(orgPrivateAttributes))
	for k := range orgPrivateAttributes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// valueMatchesShape reports whether v is acceptable for the declared shape.
func valueMatchesShape(v string, shape attrShape) bool {
	if v == "" || len(v) > maxAttrValueLen || pathishPattern.MatchString(v) {
		return false
	}
	switch shape {
	case shapeBool:
		return v == "true" || v == "false"
	case shapeSlug:
		return isSlug(v)
	case shapeToken:
		return isToken(v)
	case shapeSeverity:
		return severityLabels[strings.ToLower(v)]
	case shapeConfidence:
		return confidenceLabels[strings.ToLower(v)]
	case shapeAdvisory:
		return AdvisoryShaped(v)
	default:
		return false
	}
}

// redactAttributes returns the subset of attrs that may be retained in mode m.
// It builds a new map; it never edits the caller's.
func redactAttributes(attrs map[string]string, m Mode) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		shape, ok := externalAttributes[k]
		if !ok && m == ModeOrgPrivate {
			shape, ok = orgPrivateAttributes[k]
		}
		if !ok || !valueMatchesShape(v, shape) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Redact produces the contributable form of an observation.
//
// It CONSTRUCTS a new observation from an allowlisted set of fields rather than
// clearing fields on a copy. That is the difference between a redactor that
// stays correct when Observation grows a field and one that silently starts
// leaking it. The fingerprint is recomputed from the redacted values for the
// same reason: a caller-supplied digest is an uninspected string, and an
// uninspected string is a channel.
//
// Returns ErrContributionDisabled in ModeDisabled, and an error for an
// observation that does not validate — nox declines to contribute anything it
// cannot fully account for.
func Redact(o Observation, m Mode) (Observation, error) {
	if m == ModeDisabled {
		return Observation{}, ErrContributionDisabled
	}
	if !m.Valid() {
		return Observation{}, fmt.Errorf("intel: refusing to contribute under unknown mode %q", string(m))
	}
	if err := o.Validate(); err != nil {
		return Observation{}, fmt.Errorf("intel: refusing to contribute an observation that does not validate: %w", err)
	}

	out := Observation{
		Ecosystem:     normalizeEcosystem(o.Ecosystem),
		Package:       normalizePackage(o.Package),
		Version:       normalizeVersion(o.Version),
		RuleID:        strings.TrimSpace(o.RuleID),
		WeaknessClass: WeaknessClass(strings.ToLower(strings.TrimSpace(string(o.WeaknessClass)))),
		Kind:          o.Kind,
		ObservedAt:    redactTimestamp(o.ObservedAt, m),
		Attributes:    redactAttributes(o.Attributes, m),
	}
	out.Provenance = redactProvenance(o.Provenance, m)
	out.Fingerprint = Fingerprint(out)
	return out, nil
}

// redactProvenance rebuilds provenance from the fields that may travel.
//
// Reference is the field most likely to carry a location — a commit URL, a
// ticket link, a trace path — so it survives only as an advisory identifier
// externally. Inside the organization a token-shaped internal reference (a
// ticket id, a trace id) is retained, because there it is a working link rather
// than a disclosure.
func redactProvenance(p evidence.Provenance, m Mode) evidence.Provenance {
	out := evidence.Provenance{
		Source:     strings.ToLower(strings.TrimSpace(p.Source)),
		SourceID:   p.SourceID,
		ObservedAt: redactTimestamp(p.ObservedAt, m),
	}
	if !isSlug(out.Source) {
		out.Source = ""
	}
	// A reporter id is only ever an opaque digest produced by SourceID. Anything
	// else — a hostname somebody wired in by hand, a repository name — is
	// dropped, and an unattributed claim simply never counts as independent.
	if !isOpaqueSourceID(out.SourceID) {
		out.SourceID = ""
	}
	if isSlug(strings.ToLower(strings.TrimSpace(p.Tool))) {
		out.Tool = strings.ToLower(strings.TrimSpace(p.Tool))
	}
	if isToken(strings.TrimSpace(p.Version)) {
		out.Version = strings.TrimSpace(p.Version)
	}
	ref := strings.TrimSpace(p.Reference)
	switch {
	case AdvisoryShaped(ref):
		out.Reference = ref
	case m == ModeOrgPrivate && isToken(ref):
		out.Reference = ref
	}
	return out
}

// redactTimestamp coarsens a timestamp for the modes that leave the
// organization. A millisecond-precision timestamp is a correlation handle: it
// links two observations to one scan run, and enough of them reconstruct a
// build schedule. Corroboration needs to know roughly when, not exactly when,
// so external modes keep the hour and drop the rest.
func redactTimestamp(s string, m Mode) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	if !m.SharesExternally() {
		return t.UTC().Format(time.RFC3339)
	}
	return t.UTC().Truncate(time.Hour).Format(time.RFC3339)
}

// isOpaqueSourceID reports whether s has the shape SourceID produces.
func isOpaqueSourceID(s string) bool {
	if len(s) != sourceIDLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// sourceIDLen is the hex length of a reporter id: 16 bytes, which is far past
// any collision concern at network scale and short enough to read in a report.
const sourceIDLen = 32

// SourceID derives the opaque, stable reporter identifier used for counting
// independent corroboration.
//
// It is an HMAC of the workspace under a locally generated salt, so it is:
//
//   - stable — the same workspace always produces the same id, which is what
//     lets the network tell "one reporter, seen twice" from "two reporters";
//   - non-reversible — the network learns that two observations share a
//     reporter, and nothing else about who that is;
//   - not guessable — without the salt, an attacker who suspects a particular
//     organization uses nox cannot confirm it by hashing candidate workspace
//     names. A plain digest of the workspace would be trivially confirmable
//     that way, which is why the salt is required rather than optional.
//
// An empty salt returns an empty id. That is the fail-closed direction: an
// empty SourceID never counts as an independent source (see
// evidence.Ledger.IndependentSources), so a misconfigured install understates
// corroboration instead of publishing a reversible identifier.
func SourceID(salt, workspace string) string {
	if strings.TrimSpace(salt) == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(salt))
	_, _ = mac.Write([]byte("nox-intel-source-v1\x00"))
	_, _ = mac.Write([]byte(strings.TrimSpace(workspace)))
	return hex.EncodeToString(mac.Sum(nil))[:sourceIDLen]
}
