# ADR 0006: Tree-sitter grammars, compiled to WebAssembly and run by wazero

- Status: Accepted
- Date: 2026-11-21
- Deciders: nox maintainers
- Supersedes: the rejection of Option C in [ADR 0001](0001-sast-structural-matching.md)

## Context

ADR 0001 chose a pure-Go lexical classifier (`core/lexctx`) over real parse
trees. It rejected CGo tree-sitter outright, because nox ships one statically
linked, pure-Go binary, and it rejected tree-sitter compiled to WebAssembly on
cost and benefit: "substantial engineering for a precision gain we have no
evidence we need". Its escape hatch was evidence that lexical context leaves
measurable accuracy behind.

That evidence now exists. The taint engine does not stop at lexical context:
for every language except Go (which uses `go/ast`) it recognizes statements,
calls, arguments, receivers and functions from a line-oriented code view, with
about 16,000 lines of hand-written recognizers across 22 languages. On the
RealVuln benchmark (`docs/benchmarks/2026-11-21-realvuln/`) nox is in the
rule-based tier, and taking apart its SQL injection misses produced, in one day,
defects that are all the recognizer approximating syntax:

- a leading string literal lost because the code view of an assignment's right
  side is trimmed before the raw text is cut to it;
- argument splitting that breaks at a comma inside a string literal;
- no way to tell a call's receiver (`$pdo->prepare("SELECT …")`) or a sibling
  argument (`new SqlCommand("SELECT …", conn)`) from an operand, which reported
  two clean precision-suite fixtures;
- a JavaScript tagged template (`` sql`… ${id}` ``) read as string building;
- a one-line Java class yielding a function with no name and no parameters.

A parse tree answers each of these exactly. The product goal is to support every
language nox scans, at that precision, which the per-language recognizers make
expensive and uneven.

## Options considered

### A — Keep extending the hand-written recognizers

No new dependency. Every defect above is fixable, and was. But each fix is
local, each language is its own recognizer, and the error class does not end:
it is the recognizer guessing at a grammar it does not have.

### B — CGo tree-sitter

Fastest and simplest to program against. Rejected, as in ADR 0001: every
release target (linux, darwin, windows on amd64 and arm64, all
`CGO_ENABLED=0` in `.goreleaser.yaml` and the Dockerfile) would need a C
cross-toolchain, the static single-artifact and air-gapped story would change,
and a fault in a grammar's C scanner would take the scan process down.

### C — Tree-sitter compiled to WebAssembly, run by wazero (CHOSEN)

The official tree-sitter C runtime and pinned upstream grammars, compiled to
WebAssembly, embedded with `go:embed`, executed by wazero, a pure-Go
WebAssembly runtime with no dependencies of its own.

- Keeps `CGO_ENABLED=0`, the static binary and trivial cross-compilation.
- Upstream grammars and runtime, not a port, so trees match upstream.
- A guest trap is a recoverable Go error, not a crashed scan, and a parse can
  be bounded by context cancellation.
- WebAssembly execution is deterministic: no clock, no randomness, no I/O
  unless the host grants it, and the host grants none.
- Costs: binary size (grammar tables, on the order of 0.5–5 MB per language),
  slower than native parsing, and a reproducible build of the `.wasm`
  artifacts that has to be pinned and verified.

### D — A pure-Go tree-sitter runtime from a third party

gotreesitter, xo/transit, and others load tree-sitter parse tables in pure Go.
Not chosen now: they are young, a project that moved off one of them reports
open crash defects (an unrecoverable stack overflow on large files) and error
trees on minified JavaScript, and nox does not take on third-party software for
something this central. They are prior art for the follow-up below.

## Decision

Adopt Option C. nox builds its own WebAssembly module from the official
tree-sitter C runtime and pinned grammars, in CI, reproducibly, and runs it
under wazero. wazero is the one new dependency. We do not depend on a
third-party Go wrapper; the host API is ours, small, and shaped by what the
analyzers need, not by tree-sitter's full surface.

Rules for the implementation:

1. **Pinned and verified artifacts.** Each grammar and the runtime are pinned by
   commit. The build is scripted and reproducible; the embedded `.wasm` carries
   a recorded SHA-256 that a test checks, and CI rebuilds and compares.
2. **One boundary crossing per parse.** The host does not walk the tree through
   per-node calls into the guest; the guest serializes the tree into a flat
   record array the host reads once.
3. **Bounded.** A parse runs under a deadline and a memory limit. A trap,
   timeout or error tree is recorded as a limitation of that file, never a
   failed scan, and the file falls back to the current recognizer.

   *Amended 2026-11-23:* the bound that decides a file is work, not time. The
   guest counts tree-sitter's progress checks (one per 100 parser operations)
   and stops a parse over 2,000 plus 64 per KiB, a count that depends only on
   the grammar and the source; it also stops a parse once every version of it
   is recovering from an error, since that tree is not used. A wall-clock
   deadline decided it first, and under heavy load a normal file missed it and
   the scan's findings changed, which broke determinism. The deadline remains
   only as a backstop for a runtime defect (1 minute plus 1 minute per MiB).
   Measurements: [docs/benchmarks/2026-11-23-treesitter-budget](../benchmarks/2026-11-23-treesitter-budget/README.md).
4. **Behind the existing boundary.** Extraction produces `taint.Unit`s today;
   the tree-sitter front end produces the same units, so the engine,
   summaries and analyzers are unchanged. Each language moves over only after
   an A/B on RealVuln and the rule-diff corpus shows it is no worse, and the
   hand-written recognizer for it is removed only after that.
5. **No network, ever.** Grammars are embedded; nothing is fetched at run time.

## Consequences

- The release binary grows; the size is measured and reported per language in
  the PR that adds each one.
- Parse throughput is measured against the current extractors on the RealVuln
  repositories before any language switches over.
- `core/lexctx` stays: it is the fallback for every file the parser declines,
  and for languages without a grammar.

## Follow-up: a pure-Go parser of our own

WebAssembly is the route to real grammars now, not the end state. The end state
is a tree-sitter-compatible runtime in pure Go that nox owns: it loads the same
parse tables (`parser.c` tables translated to Go data) and runs the GLR parser,
lexer and external scanners natively, with no WebAssembly runtime. The
host API from rule 4 is the seam: the WebAssembly front end and a native one
produce the same `taint.Unit`s, so the switch is per language and testable.

Start it when one of these holds, and not before:

- parse time is a measured, material share of scan time;
- binary size from the embedded grammars is a measured problem for users;
- wazero itself becomes a constraint (platform support, a defect, its own
  dependency policy).

The gate for switching any language to the native runtime is tree equality
with the WebAssembly runtime on that grammar's upstream test corpus and on the
RealVuln repositories, the same way transit and gotreesitter compare against
the C runtime. External scanners are hand-ported per grammar; that is the bulk
of the work and the reason this is deferred.
