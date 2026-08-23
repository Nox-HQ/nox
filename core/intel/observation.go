package intel

import (
	"fmt"
	"time"

	"github.com/nox-hq/nox/core/evidence"
)

// WeaknessClass names the kind of weakness observed, in the network's shared
// vocabulary. It is a slug, never prose: a free-text description is a channel
// for source code, prompts, and customer data to escape, and there is no
// reliable way to filter prose after the fact.
type WeaknessClass string

// Weakness classes nox currently reports. The set is open — a new analyzer may
// introduce a class without a change here — but every value must be slug-shaped
// (see Validate), so the openness cannot be used to smuggle content.
const (
	// WeaknessPromptInjection — untrusted input reaches a model prompt without
	// an intervening boundary.
	WeaknessPromptInjection WeaknessClass = "prompt-injection"
	// WeaknessUnsafeToolExposure — an MCP or agent configuration exposes a tool
	// with more authority than the surrounding trust boundary justifies.
	WeaknessUnsafeToolExposure WeaknessClass = "unsafe-tool-exposure"
	// WeaknessKnownVulnerableDependency — a dependency version falls inside a
	// published advisory's affected range.
	WeaknessKnownVulnerableDependency WeaknessClass = "known-vulnerable-dependency"
	// WeaknessSecretExposure — a credential was found where it should not be.
	WeaknessSecretExposure WeaknessClass = "secret-exposure"
	// WeaknessMaliciousPackage — the package itself behaves maliciously
	// (install hooks, exfiltration, typosquatting).
	WeaknessMaliciousPackage WeaknessClass = "malicious-package"
	// WeaknessInsecurePromptLogging — prompts or model responses are written to
	// a log sink that is not treated as sensitive.
	WeaknessInsecurePromptLogging WeaknessClass = "insecure-prompt-logging"
	// WeaknessUnpinnedModel — a model or prompt artifact is referenced without
	// a pin, so what runs tomorrow is not what was reviewed today.
	WeaknessUnpinnedModel WeaknessClass = "unpinned-model"
)

// Observation is one environment's report that one weakness was seen in one
// artifact. It is the atom of the network, and the only structure that ever
// crosses a trust boundary.
//
// Every field is a public coordinate or an opaque token. There is deliberately
// no field for a file path, a line number, a matched string, a message, or a
// snippet: the type cannot carry them, so no redaction bug can leak them.
type Observation struct {
	// Fingerprint is the deterministic identity of the weakness-in-artifact.
	// It is advisory on input: Fingerprint and Redact recompute it, and
	// Aggregate ignores whatever a reporter supplied, because clustering on an
	// attacker-chosen identity is how unrelated reports get merged.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Ecosystem is the package ecosystem: npm, go, pypi, maven, cargo.
	Ecosystem string `json:"ecosystem"`
	// Package is the artifact identifier within that ecosystem. It must be a
	// package name, not a path — see Validate.
	Package string `json:"package"`
	// Version is the concrete version observed, if known.
	Version string `json:"version,omitempty"`
	// RuleID is the nox rule that produced the observation.
	RuleID string `json:"rule_id"`
	// WeaknessClass is the shared-vocabulary class of the weakness.
	WeaknessClass WeaknessClass `json:"weakness_class"`
	// Kind is how the claim was established, on core/evidence's single scale.
	Kind evidence.Kind `json:"kind"`
	// Provenance identifies the reporting subsystem and — opaquely — the
	// reporter, so independent corroboration can be counted without learning
	// who anybody is.
	Provenance evidence.Provenance `json:"provenance"`
	// Attributes carries bounded, allowlisted facts. Keys outside
	// AllowedAttributeKeys are dropped by Redact, and every allowlisted key
	// constrains the shape of its value.
	Attributes map[string]string `json:"attributes,omitempty"`
	// ObservedAt is an RFC3339 timestamp supplied by the caller; the package
	// never reads a clock.
	ObservedAt string `json:"observed_at"`
}

// Observation bounds. They are enforced rather than documented because an
// unbounded map is a covert channel: a thousand short allowlisted values can
// carry as much as one long disallowed one.
const (
	maxAttributes     = 24
	maxAttrKeyLen     = 64
	maxAttrValueLen   = 128
	maxSummaryLen     = 200
	maxAdvisoriesKept = 64
)

// Validate reports whether the observation is well formed enough to be
// fingerprinted, clustered, stored, or contributed.
//
// It is strict about shape on purpose. Each rule closes a channel:
//
//   - Ecosystem and Package are required and must be package-shaped, because
//     the network only carries claims about artifacts that are identifiable to
//     everyone. An observation with no package is a claim about the reporter's
//     own code, and nox will not contribute those at all.
//   - WeaknessClass and RuleID must be slug- and identifier-shaped, so neither
//     can be used as a free-text field.
//   - Attributes are bounded in count and length.
//   - ObservedAt must parse as RFC3339, so downstream ordering is total and no
//     caller can smuggle a string through a timestamp.
func (o Observation) Validate() error {
	if !isEcosystem(o.Ecosystem) {
		return fmt.Errorf("intel: invalid ecosystem %q", o.Ecosystem)
	}
	if !isPackageName(o.Package) {
		return fmt.Errorf("intel: invalid package name %q (a package identifier is required; paths and content are never accepted)", o.Package)
	}
	if o.Version != "" && !isVersionExpr(o.Version) {
		return fmt.Errorf("intel: invalid version %q", o.Version)
	}
	if !isRuleID(o.RuleID) {
		return fmt.Errorf("intel: invalid rule id %q", o.RuleID)
	}
	if !isSlug(string(o.WeaknessClass)) {
		return fmt.Errorf("intel: invalid weakness class %q (must be a slug, never free text)", o.WeaknessClass)
	}
	if !o.Kind.Valid() {
		return fmt.Errorf("intel: invalid evidence kind %q", o.Kind)
	}
	if !isSlug(o.Provenance.Source) {
		return fmt.Errorf("intel: invalid provenance source %q", o.Provenance.Source)
	}
	if len(o.Attributes) > maxAttributes {
		return fmt.Errorf("intel: %d attributes exceeds the limit of %d", len(o.Attributes), maxAttributes)
	}
	for k, v := range o.Attributes {
		if len(k) > maxAttrKeyLen {
			return fmt.Errorf("intel: attribute key %q exceeds %d bytes", truncateForError(k), maxAttrKeyLen)
		}
		if len(v) > maxAttrValueLen {
			return fmt.Errorf("intel: attribute %q has a value exceeding %d bytes", truncateForError(k), maxAttrValueLen)
		}
	}
	if err := validateRFC3339(o.ObservedAt, "observed_at"); err != nil {
		return err
	}
	if o.Provenance.ObservedAt != "" {
		if err := validateRFC3339(o.Provenance.ObservedAt, "provenance.observed_at"); err != nil {
			return err
		}
	}
	return nil
}

// validateRFC3339 checks a caller-supplied timestamp. Parsing is not a clock
// read: it establishes an ordering without consulting the current time.
func validateRFC3339(s, field string) error {
	if s == "" {
		return fmt.Errorf("intel: %s is required (callers supply time; this package never reads a clock)", field)
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return fmt.Errorf("intel: %s %q is not RFC3339: %w", field, truncateForError(s), err)
	}
	return nil
}

// truncateForError bounds a value echoed back in an error message. An error
// string ends up in logs and CI output, which is precisely where a rejected
// secret must not be reproduced in full.
func truncateForError(s string) string {
	const limit = 24
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
