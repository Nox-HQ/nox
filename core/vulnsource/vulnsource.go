// Package vulnsource is the seam between nox's dependency analysis and whatever
// answers the question "is this package version known to be vulnerable?".
//
// Nox has always asked that question over the network — core/analyzers/deps has
// queried api.osv.dev by default since dependency scanning existed. What keeps
// nox offline-first is not the absence of network code but three properties
// this package is built to preserve:
//
//  1. the capability is switchable off;
//  2. a failed lookup degrades loudly, never into a silent clean scan;
//  3. nothing downstream depends on a source having answered.
//
// A Source implementation owns its own wire protocol entirely. Batching limits,
// ecosystem vocabularies, detail hydration, and the quirks of a particular API
// are implementation business; this package defines only the semantic contract.
//
// # Record shape
//
// Record is deliberately OSV-wire-compatible, json tags included. OSV's schema
// is the interchange baseline every source must be able to speak, which is what
// makes a richer source verifiable against a reference one rather than merely
// asserted to be a superset of it. Sources with more to say extend Record; they
// do not reshape it.
package vulnsource

import "context"

// Query is one package to look up. Ecosystem is nox's own internal ecosystem
// name ("go", "npm", "pypi", ...); mapping it to a wire vocabulary belongs to
// the implementation, which alone knows what its API accepts.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// Record is a single hydrated vulnerability.
//
// "Hydrated" is part of the contract, not an implementation detail. OSV's batch
// endpoint answers only {id, modified}; a source that returned those directly
// would report every dependency finding at SeverityMedium with an empty
// summary, and since enforcing gates key on high/critical, a critical CVE could
// never block a build. A Source returns records whose severity and affected
// ranges are populated, or it degrades and says so.
type Record struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Aliases  []string   `json:"aliases"`
	Severity []Severity `json:"severity"`
	Affected []Affected `json:"affected"`

	// DatabaseSpecific carries source-database annotations. GitHub advisories
	// publish a coarse severity label here, which is the only severity signal
	// available for records that carry a CVSS v4 vector and nothing else.
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`

	// Intelligence is what a source knows beyond the advisory: epistemic
	// status, corroboration across distinct reporters, and the evidence ledger
	// behind it. Nil for a plain advisory database, which is the honest
	// representation — OSV makes no such claims.
	//
	// It is namespaced under nox_intelligence so a record round-trips through
	// the OSV wire format without colliding with anything OSV may add.
	Intelligence *Intelligence `json:"nox_intelligence,omitempty"`
}

// Status returns the record's epistemic standing, resolving a record with no
// intelligence block to PUBLISHED — which is what an advisory database returns.
func (r *Record) Status() Status {
	if r.Intelligence == nil {
		return StatusPublished
	}
	return r.Intelligence.Status.EffectiveStatus()
}

// Theoretical reports whether the record describes an undemonstrated path.
func (r *Record) Theoretical() bool { return r.Intelligence.Theoretical() }

// DatabaseSpecific holds the subset of source-specific annotations nox reads.
type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// Severity holds a CVSS or other severity score.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Package identifies a package by name and ecosystem, in wire vocabulary.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Affected describes packages and version ranges affected by a vulnerability.
type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

// EcosystemSpecific carries per-ecosystem detail. For Go, advisories are scoped
// to the import paths they actually affect — a module-level match alone
// overstates exposure (e.g. GO-2026-5932 affects only x/crypto/openpgp, not
// every consumer of x/crypto). Dropping this field does not lose a finding; it
// silently inflates the severity of one that should have been demoted.
type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

// Import is a single affected import path within a module.
type Import struct {
	Path string `json:"path"`
}

// Range is a version range with events marking introduction / fix.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is a single point in a version range. Either Introduced or Fixed (or
// LastAffected) is populated; the others are empty.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Source resolves package queries to known vulnerabilities.
//
// Lookup is batch-shaped on purpose. A per-package Lookup(ecosystem, pkg,
// version) reads more naturally but discards the batching real vulnerability
// APIs are built around — OSV accepts 1000 queries per request — turning one
// round trip into one per dependency.
//
// The returned map is keyed by the caller's index into qs, so a source is free
// to skip queries it cannot serve without the caller losing track of which
// answer belongs to which package. Indices absent from the map mean "no
// vulnerabilities", which is why a source that could not complete a lookup must
// record a degradation rather than return an empty map and let it read as
// clean.
//
// A returned error means the lookup could not be attempted at all. Failures
// that are expected in normal operation — an unreachable network, a rejected
// request — are degradations, not errors: they return partial results so a scan
// keeps whatever it did learn.
type Source interface {
	// Name identifies the source in degradation records and provenance.
	Name() string

	// Lookup resolves qs to hydrated records, keyed by index into qs.
	Lookup(ctx context.Context, qs []Query) (map[int][]Record, error)
}
