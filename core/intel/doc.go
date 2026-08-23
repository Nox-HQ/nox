// Package intel implements nox's vulnerability intelligence network: the path
// from a local observation to a corroborated candidate, a validated
// vulnerability, and an organization-specific exposure.
//
// The lifecycle it models is:
//
//	Observation  — one scan saw one weakness in one artifact.
//	Candidate    — several observations of the same artifact clustered together.
//	Validated    — evidence strong enough to assert the vulnerability is real.
//	Exposure     — what that vulnerability means in THIS environment.
//	Blast radius — which services, capabilities, identities and data it reaches.
//	Containment  — what would shrink that reach, and by how much.
//
// Confidence is never computed here. Every judgment delegates to
// core/evidence's Ledger, which already encodes the two rules this package
// exists to respect: volume is not corroboration (one project scanning itself a
// thousand times is still one source), and no semantic claim reaches CONFIRMED
// on its own. A second scoring scheme would inevitably disagree with the first,
// and the disagreement would surface as a confident-looking wrong answer.
//
// # Privacy contract
//
// The product is "share security facts, not customer artifacts". The facts
// worth sharing are about publicly identifiable artifacts — an ecosystem, a
// package, a version, a weakness class. Everything else an observation touches
// (file paths, source, prompts, secrets, identities, customer data) is the
// property of the environment that ran the scan and must never be able to leave
// it, whether or not anyone remembered to write a rule against it.
//
// Four structural properties enforce that, in preference to filtering:
//
//  1. Contribution is opt-in. The zero configuration is ModeDisabled, and
//     Redact returns ErrContributionDisabled in that mode rather than quietly
//     producing nothing — a silent no-op is indistinguishable from a leak that
//     happened to be empty.
//  2. Redact BUILDS a fresh observation out of an allowlisted set of fields
//     instead of deleting fields from the caller's. A field added to Observation
//     next year is therefore absent from contributions until somebody
//     deliberately adds it to the redactor.
//  3. Attributes are constrained by key AND by value shape. A key allowlist
//     alone is not enough: nothing stops a caller putting an API key in an
//     allowlisted key, so each allowlisted key also declares the shape of value
//     it may carry (a boolean, a severity label, a CWE id, a slug).
//  4. Fingerprints hash only public coordinates. Hashing a file path or a
//     source snippet would make the digest itself a carrier of customer data —
//     confirmable by anyone who can guess the input.
//
// # Determinism
//
// The package is pure: no clock, no network, no global state. Callers pass
// RFC3339 timestamps. The same inputs produce the same fingerprints, the same
// confidence, and the same byte-for-byte serialization; collections are sorted
// before they are emitted. The only I/O is Store, which reads and writes local
// JSON files.
package intel
