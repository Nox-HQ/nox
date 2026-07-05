# ADR 0001: Structural matching for SAST false-positive suppression

- Status: Accepted
- Date: 2026-07-05
- Deciders: nox maintainers
- Supersedes: —

## Context

Nox's SAST rules (secrets, ai, variants, …) match regexes against raw file
**text**. A regex has no idea whether the bytes it matched are live code, the
contents of a string literal, or a comment. As a result a single broad pattern
fires equally on:

- a real hardcoded secret in a code assignment (a true positive),
- the same byte sequence buried inside a base64 data-URI / SVG blob,
- a lockfile hash or a minified-JS chunk,
- a commented-out line or a prose comment.

The scan-of-the-week reports put the resulting noise at ~99.5% for the broad
rule classes. Almost all of that noise is patterns firing in **non-code text**.
The users who hit it stop trusting the tool.

The fix is to only trust a match that sits in real code. That requires knowing,
for a given byte offset, whether it is code, string, or comment — i.e. some
degree of structural (rather than purely textual) understanding of the file.

Three implementation strategies were evaluated. The overriding constraint is
non-negotiable and predates this ADR:

> **nox ships a single, statically-linked, pure-Go binary with no CGo.** This is
> load-bearing for the air-gapped / hermetic-CI story: one artifact, no shared
> libraries, no runtime toolchain, reproducible builds, trivial cross-compile.

## Options considered

### Option A — Pure-Go lexical-context classifier (CHOSEN)

Hand-rolled, dependency-free byte scanners (one per language family) that
partition a file into `code` / `string` / `comment` regions. Analyzers gate
each raw match: drop it if it lies in a comment, or in a string that is a *data
blob* rather than a short literal (so genuine hardcoded-secret-in-string
findings survive). Implemented in `core/lexctx`.

- **Pros**
  - Zero new dependencies; pure Go; keeps the single static binary intact.
  - Deterministic and offline — same input, same regions, always. No network,
    no model, no generated parser tables to ship.
  - Cheap: a single linear pass over the bytes, no allocation-heavy AST.
  - Graceful degradation: an unknown language returns one big code region, so
    gating is *never worse than today* — it only ever removes provably non-code
    matches.
  - Incrementally adoptable: analyzers opt in with a ~5-line post-filter
    (`SuppressNonCode` / `InCode`), no pipeline rewrite.
- **Cons**
  - Not a real parser. It tracks lexical context (string/comment/interpolation),
    not grammar. It handles the cases that actually cause FPs — f-strings,
    template-literal `${}` interpolation, raw/byte strings, regex-vs-division,
    triple-quoted blobs, `#`/`//` inside strings — but it will never reason about
    scopes, types, or data flow.
  - One scanner per language family to write and maintain (Python and JS/TS
    cover the bulk of nox's SAST surface today; others degrade to all-code).

### Option B — CGo tree-sitter (real ASTs) — REJECTED

Bind `go-tree-sitter` and ship per-language grammars for precise parse trees.

- **Pros**: real ASTs; battle-tested grammars; node-kind queries are far more
  expressive than lexical regions.
- **Cons / why rejected**: **CGo breaks the pure-Go single-static-binary core
  guarantee** — the decision that is explicitly out of scope to relitigate here.
  CGo brings a C toolchain into the build, complicates and slows
  cross-compilation, risks glibc/musl portability issues in minimal/air-gapped
  images, and undermines reproducibility. The precision win does not justify
  giving up the deployment properties that are central to nox's value. **Not in
  core, now or later.**

### Option C — WASM-embedded grammars — REJECTED

Compile tree-sitter grammars to WASM and run them via a pure-Go WASM runtime
(e.g. wazero), keeping CGo out.

- **Pros**: real grammars without CGo; stays single-binary-ish.
- **Cons / why rejected**: embeds megabytes of grammar blobs per language,
  bloating the binary; adds a WASM runtime and its startup/marshalling overhead
  on a hot path; determinism and reproducibility now depend on the runtime and
  the pinned grammar artifacts; substantial engineering for a precision gain we
  have no evidence we need. Rejected for core on cost/benefit grounds.

## Decision

Adopt **Option A**, the pure-Go lexical-context classifier (`core/lexctx`), as
the chosen path for SAST false-positive suppression. It removes the dominant FP
class (matches in comments and data blobs) while preserving the pure-Go,
single-static-binary, deterministic, offline guarantees that define nox.

Options B and C are rejected for **core**. Tree-sitter remains conceivable only
as a **future opt-in, out-of-core module** (e.g. a separately built plugin a
user explicitly installs) — and only if a precision benchmark later proves that
lexical context leaves real, measurable accuracy on the table that scope/type/
data-flow analysis would recover. Absent that evidence, we do not pay the cost.

## Consequences

- `core/lexctx` provides `Classify`, `KindAt`, `InCode`, `SuppressNonCode`, and
  `LineColToOffset`. Analyzers adopt it as an additive post-filter; the demo
  integration test wires it into the real secrets analyzer and shows the
  AWS-key finding count collapse from 3 → 1 (dropping the base64-blob and
  comment FPs, keeping the true code secret).
- The classifier is a **suppression** aid, not a detector: it can only ever
  *remove* matches, and only when it is confident they are non-code. A
  misclassification therefore fails safe — it keeps a match it might have
  dropped; it never invents one.
- New language support is bounded work (one scanner per family); until a
  language is added it degrades to all-code, i.e. today's behavior.
- **Follow-up (out of scope here):** flip individual analyzers (secrets, ai) to
  consume the filter behind a config flag, then measure the FP-rate delta on the
  scan-of-the-week corpus. If precision plateaus below expectations, revisit a
  tree-sitter opt-in module per the escape hatch above.
```
