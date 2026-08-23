// Package attack is nox's dynamic exploit-validation engine: the generalized
// successor to core/confirm. It takes what the static scan learned, constructs
// grounded exploit hypotheses, safely exercises a running target, and produces
// reproducible, evidence-backed attack traces. The workflow is
// Discover → Analyze → Hypothesize → Attack → Verify → Reproduce → Regress.
//
// This is an ACTIVE capability. It sends attack traffic — adversarial payloads —
// at a target the operator supplies and isolates. It is NEVER part of `nox scan`:
// scanning is read-only and offline, whereas this package deliberately probes a
// live system. It is opt-in, gated behind a distinct command, and refuses to run
// unless the safety profile permits network traffic AND the caller passed
// explicit authorization. Those refusals are structural (enforced in Run before
// any byte leaves the process), not advisory.
//
// Two correctness properties are load-bearing and are carried over from
// core/confirm:
//
//   - Reflection immunity. A violation is scored ONLY on a canary value that is
//     never present in any payload we send (see canary.go). A target that merely
//     echoes our input can therefore never be mistaken for one that obeyed an
//     injected instruction — the difference between a real exploit and a random
//     payload cannon.
//   - Evidence over opinion. Every verdict is produced by evidence.Derive-
//     Exploitability from a ledger of claims, never by this package inventing a
//     state transition. Deterministic oracles are primary; a semantic judgment
//     can never, on its own, reach CONFIRMED.
//
// The package is pure and deterministic: it reads no clock (callers pass an
// RFC3339 Now), seeds all derivation explicitly, and sorts every map iteration
// before emitting, so the same inputs produce byte-identical output.
package attack
