# Integer overflow in Go — why `MEMSAFE-001` is not gosec's `G115`

Status: implemented. Companion to [`go-taint.md`](./go-taint.md), which explains
why nox parses Go with `go/ast`. This document explains what that choice costs
for a rule that wants types, and why the rule that shipped is deliberately a
different — and much narrower — rule than the one it replaces.

## The gap

gosec was removed from the fleet's shared golangci config. `G115` (integer
overflow in a type conversion) was its largest uncovered class by a wide
margin. The obvious task was to reimplement it.

Measuring gosec first made that the wrong task.

## `go/types` is not available to nox, and the reason is structural

nox parses Go with `go/parser` + `go/ast` + `go/token`. It has never used
`go/types`. That is not an oversight, and it is not cheap to change.

`G115` as gosec defines it needs full type resolution: to know that
`int32(l.StartLine)` narrows, you must resolve `l`'s type, find `StartLine` on
it, and learn that the field is an `int`. `go/ast` gives you the identifier and
nothing else.

Resolving that needs `go/types` with a working `Importer`, and every available
importer has the same prerequisite — a resolvable module graph:

| Importer | Needs |
|---|---|
| `importer.Default()` | compiled export data in `GOROOT`/build cache |
| `importer.ForCompiler(fset, "source", nil)` | every dependency's **source**, on disk |
| `golang.org/x/tools/go/packages` | shells out to `go list`; a Go toolchain **and** a resolvable module graph |

Measured directly — a `types.Config{Importer: importer.Default()}` run over a
six-line file that imports a module not present in the cache fails outright:

```
typecheck err: could not import github.com/some/external/pkg
  (cannot find package … in any of: $GOROOT/src, $GOPATH/src)
Check returned err: could not import …
```

Stdlib-only files type-check fine. Anything else does not.

This collides with three properties nox is built on:

1. **Offline by construction.** `nox scan --offline` guarantees zero network.
   Type-checking a repo whose module cache is cold requires `go mod download`.
2. **No toolchain assumption.** nox ships as a single static CGo-free binary and
   scans checked-out trees — in CI containers, in pre-commit hooks, in images
   with no Go installed. `go list` is not available there.
3. **Determinism.** A scan is a pure function of the bytes on disk. Type
   checking makes the result depend on what happens to be in the module cache,
   so the same commit can scan differently on two machines.

gosec does not have this problem because gosec runs **inside the project's own
build**, where the module graph is already resolved. nox is not in that
position and adopting it would be a change of product category, not a feature.

**Cost of closing the gap properly**: a `go/types` mode would need a new
dependency (`x/tools`), a network/toolchain precondition, per-package caching,
and a documented degradation path for every repo that cannot be type-checked —
for a rule class whose measured value is described below. It was not worth it.

### What that costs in recall, measured

Of gosec's 11 `G115` findings on nox's own source, 7 (64%) name a type that
only `go/types` could resolve — struct fields from another package
(`findings.Location.StartLine`), and named types with integer underlying types
(`findings.FingerprintVersion`, `os.FileMode`). Those are permanent false
negatives for an AST-only analyzer, and the package doc says so.

## Why reimplementing `G115` would have been actively harmful

Before writing anything, gosec was run across sixteen fleet Go repositories plus
nox itself.

| Rule | Findings | True positives |
|---|---|---|
| `G115` integer overflow | 96 | **0** |
| `G103` use of `unsafe` | 20 | **0** |
| `G602` slice out of bounds | 13 | **0** |

Every one of the 96 `G115` findings is correct code:

- `int32(len(out))`, `int32(total)`, `int32(limit)` — filling protobuf count
  fields. 70 of the 96.
- `uint64(t.Unix())` — an HOTP counter, positive until the year 292 billion.
- `byte(addr>>24)`, `byte(addr>>16)`, `byte(addr)` — IPv4 octet extraction,
  where truncation is the entire point.
- `byte(nano%10)` — digit formatting behind a modulo that provably fits.
- `os.FileMode(hdr.Mode)&0o777|0o755` — masked to nine bits on the same line.

That is the shape of a rule people suppress rather than fix, and they already
have: 63 `#nosec G115` suppressions exist across that fleet.

All 20 `G103` findings sit in generated `*.pb.go` files, from protoc-gen-go's
own `unsafe.Slice(unsafe.StringData(...))` idiom. There is no hand-written
`unsafe` in the fleet at all. All 13 `G602` findings are three lines in one file
reported four times each, plus one already carrying a `//nolint` with a comment
explaining the guard.

## The rule that shipped

`MEMSAFE-001` reports the shape where truncation is a memory-safety bug rather
than a style question: **a value that is narrowed, or flipped signed→unsigned,
and then used to size an allocation or bound a slice.**

Everything is function-local. Source types come from parameters, results, `var`
declarations, explicit conversions, and a small table of stdlib functions with
fixed integer return types. A conversion whose operand type cannot be
established locally is not reported.

### Sinks

- `make(T, n)` / `make(T, n, m)` — allocation length and capacity.
- `s[lo:hi]`, `s[lo:hi:max]` — slice bounds.

A bare **index** `s[i]` is deliberately not a sink. Syntactically it is
indistinguishable from a map lookup, where an index is not a bounds context at
all — telling them apart needs `go/types`. And Go bounds-checks every slice
index, so a wrapped index panics rather than reading out of bounds; the harm is
capped at the denial of service the slice-bound case already covers. Measured
on the Go standard library, treating indexes as sinks produced 46 findings,
every one correct code: AES S-box lookups, Latin-1 property tables, and a
`map[uint64]string` in the linker.

`copy` and `append` are not sinks either: they are bounded by the slices they
operate on.

### Suppressions

Each one removes a class that was observed firing on correct code:

| Suppression | Removes |
|---|---|
| mask fitting the destination (`x & 0xFF`) | byte extraction |
| modulo, any divisor | table confinement (`h % buckHashSize`) |
| logical shift on an unsigned value (`x >> 24`) | AES S-box, binary-search midpoints |
| comparison guard, seen through a conversion (`if uint32(r) <= MaxLatin1`) | the stdlib's own range-check idiom |
| `len`/`cap`-derived, destination ≥ 32 bits | `uint32(2*len(buf))` |
| constant expressions | `int32(4*1024)` |

`len`-derived values narrowed to **16 bits or fewer** are still reported: a
slice longer than 65535 is entirely ordinary.

## Measured behaviour

| Corpus | Go files | gosec `G115` | `MEMSAFE-001` |
|---|---|---|---|
| nox itself | 638 | 11 (0 real) | **0** |
| 16 fleet repos + warden | 2,803 | 85 (0 real) | **0** |
| Go standard library | 6,822 | not run | **0** |
| Go module cache (third-party) | 116,032 | — | **18** |

On `segmentio/kafka-go` specifically, where a real bug lives: gosec reports
**156** `G115` findings, two of which are the bug. `MEMSAFE-001` reports
**one**, and it is the bug.

Of the 18 module-cache findings (≈15 distinct sites, several repeated across
module versions), auditing every one:

**Genuine, remotely triggerable (3):**

- `IBM/sarama` `broker.go:1593` —
  `make([]byte, int32(binary.BigEndian.Uint32(header)))`. A four-byte length
  from the network, sign-flipped; a peer sending ≥ 2³¹ makes `make` panic.
- `segmentio/kafka-go` `saslauthenticate.go:44` — the identical shape.
- `rabbitmq/amqp091-go` `write.go:246` — `uint8(len(b))` declared as the frame
  length, then `w.Write(b[:length])`. A string longer than 255 bytes is
  silently mis-framed.

**Defensive / weak (3 sites):** `hashicorp/go-msgpack` and `ugorji/go/codec`
convert an `io.Reader.Read` result to `uint` before a slice bound — safe by the
`io.Reader` contract, unsafe against a misbehaving implementation.

**False positives (9 findings across ~7 sites):** `gonum/mat/pool.go`
(`uint(r*c)` on documented-precondition dimensions), `ristretto` and
`bytedance/sonic` (`uintptr` alignment and code-size arithmetic that is provably
small), `k8s.io/apimachinery` (a marshal-path size the code checks immediately
after).

So: roughly one finding per 6,400 files of third-party Go, about 40% precision
by distinct site, and it finds real remote-DoS bugs in widely deployed
networking libraries. That is a rule worth keeping. A 1.3%-precision rule is
not.

## Severity, and whether it gates

**Medium / Medium confidence — it does NOT gate the fleet**, whose CI fails only
on net-new critical/high.

That is deliberate. The rule produced zero findings across nox and every fleet
repository, so nothing about the gate changes today either way. Promoting it to
high would make a rule with no observed true positive *in this fleet* able to
turn builds red, on the strength of third-party evidence and synthetic fixtures
alone. Medium reports it, people can see it, and the severity can be raised once
there is field evidence from these repositories rather than from the module
cache.

## The other three gosec rules

- **`G103` (`unsafe`)** — not implemented. All 20 fleet findings are in
  generated protobuf code, which this analyzer skips on principle. There is no
  hand-written `unsafe` in the fleet to find. Worth revisiting only if that
  changes; a bare "you used `unsafe`" report is an inventory, not a finding.
- **`G602` (slice bounds)** — not implemented as a separate rule. The valuable
  half of it is exactly what `MEMSAFE-001`'s slice-bound sink already covers,
  with the overflow requirement making it precise. gosec's own 13 findings were
  three lines reported four times each.
- **`G104` (unhandled errors)** — **should be left to `errcheck`**, which is
  still enabled in the fleet's golangci config and covers this class properly,
  with per-package configuration people have already tuned. Reimplementing it in
  nox would mean two tools reporting the same thing under two rule IDs — the
  precise duplication that retired `nox-plugin-sast` (see the `weakcrypto`
  package comment) and the ten IaC rule IDs in 1.23.0. Recommended: do not
  implement.
