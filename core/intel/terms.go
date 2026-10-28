package intel

// WireSchemaVersion is the contribution schema this build speaks. Schema 1
// (nox <= 1.49.0) carried no consent; the service accepts it only as legacy.
const WireSchemaVersion = 2

// TermsVersion names the current contribution terms. It is sent as
// consent_version and recorded locally when an operator accepts. Changing the
// text of Terms without changing this string would let an operator be bound to
// words they never saw, so TestTermsVersionPinsTheText fails until both move.
const TermsVersion = "2026-10"

// Terms is the one place the contribution terms are written. `nox intel
// consent`, `nox intel preview` and the docs all print this constant.
//
// REQUIRES OWNER REVIEW BEFORE RELEASE: this is user-facing terms text.
const Terms = `NOX Intelligence contribution terms, version 2026-10

Contribution is optional. Scanning, and asking NOX Intelligence for
advisories, work the same with it off. It stays off until you turn it on
(scan.intelligence.contribute: true) AND accept these terms on this machine.

What is sent
  For each vulnerable dependency a scan finds, one observation containing only
  the fields printed by "nox intel allowlist": a fingerprint, the package
  ecosystem, name and affected version range, the weakness class, the nox rule
  id, an opaque id for this installation, a timestamp, the nox version, the
  terms version you accepted, and a hash that lets only you erase your id.

What is never sent
  Source code, file contents, file paths, repository names, code snippets,
  secrets, prompts, model output, or findings from any rule other than
  dependency vulnerabilities. Your reporter id is derived from a secret that
  stays on this machine and reveals nothing about you.

What the service does with it
  It counts how many distinct installations reported the same issue, and may
  publish a record derived from many reports. A published record never contains
  a reporter id. Nothing is published without review by a person.

How long identifiers are kept
  By default the service removes reporter ids from unpublished reports 90 days
  after the last activity. A removed report still counts as having been made,
  but is no longer linked to you. A self-hosted service may use another period.

How to erase and withdraw
  "nox intel forget" removes your reporter id from every report on the service
  (including published ones) and turns contribution off on this machine.
  "nox intel consent withdraw" turns it off without contacting the service.

If these terms change, contribution pauses until you accept the new version.
`
