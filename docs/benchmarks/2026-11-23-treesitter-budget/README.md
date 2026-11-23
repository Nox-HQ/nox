# Tree-sitter parse budget and module sizes

Measured 2026-11-23 on an Apple M5 (10 cores), nox at `main` 5caa459 plus the
work budget, tree-sitter v0.27.2 in wazero. Corpus: every Python, JavaScript,
TypeScript, TSX and Java file of at most 2 MiB in the 203 RealVuln
repositories, vendored and minified files included: 44,857 files, 298 MiB.
Harness: `TestMeasureCorpus` in `core/treesitter/measure_test.go`.

## Why the budget counts work

A parse used to be bounded by a deadline of 5 s plus 5 s per MiB. On
2026-11-23, with the load average between 100 and 230, a normal Python file
missed it, fell back to the line reader, and the scan reported two fewer
findings than the same binary on the same tree at normal load. A bound that
reads the clock makes the output depend on the machine.

The bound is now the number of progress checks the guest makes. Tree-sitter
calls a progress callback once per 100 parser operations, and the operations
a parse takes depend only on the grammar and the source. Two runs of the whole
corpus, the first at a load average of 12 and the second between 5 and 14,
counted the same checks for all 44,857 files.

## Work per language

Checks per KiB of source, and throughput of the unbounded parse, including
decoding the tree on the host. The machine was shared during the run, so
throughput is indicative; checks are exact.

| Language | Files | MiB | MiB/s | Checks/KiB p50 | p99 | max | Most checks, one file |
|---|---:|---:|---:|---:|---:|---:|---:|
| Java | 25,717 | 133.8 | 2.39 | 4.3 | 8.9 | 15.3 | 3,309 |
| JavaScript | 7,288 | 104.4 | 1.31 | 6.6 | 19.8 | 26.1 | 19,719 |
| Python | 3,173 | 23.7 | 1.51 | 6.7 | 14.1 | 27.6 | 3,849 |
| TSX | 1,383 | 7.4 | 1.57 | 6.4 | 10.3 | 11.4 | 543 |
| TypeScript | 7,296 | 28.7 | 1.54 | 7.0 | 11.5 | 21.7 | 1,535 |

No file under 4 KiB took more than 75 checks. The 149 trees that needed error
recovery took at most 15.5 checks per KiB.

`DefaultBudget` gives a parse 2,000 checks plus 64 per KiB: every corpus file
fits, with 2.3 times the costliest file's ratio to spare.

## Error recovery

Checks bound work, not time. In error recovery one check costs about ten times
what it costs in source. Bytes that are not source, read as JavaScript, took
30 s to over 50 s for 300 KB, and for a repeating byte pattern the checks grew faster
than the input: 16 per KiB at 8 KiB, 54 at 64 KiB, 206 at 300 KB. `ParseFile`
therefore also stops a parse at the first check where every parse version is
recovering from an error. The tree would contain an ERROR node, and the taint
front ends fall back on any error tree.

| Input | Unbounded | With the stop |
|---|---:|---:|
| 300 KB uniformly random bytes as JavaScript | over 50 s | 5 ms |
| 300 KB repeating byte pattern as JavaScript | 30 s | 13 ms |
| 2 MiB of either | not run | 5 ms, 13 ms |
| `core/scan.go` (130 KB of Go) as JavaScript | 0.6 s | 0.2 s |
| `core/scan.go` as Python | 1.6 s | 0.5 s |

On the corpus the stop fired on 3 files, and each of them also gave an error
tree when parsed to the end. No parse the stop ends would have produced a
clean tree.

## Module sizes

Embedded in the binary (`core/treesitter/wasm`), the tree-sitter runtime
included in each:

| Module | Languages | Bytes |
|---|---|---:|
| `java.wasm` | Java | 529,554 |
| `javascript.wasm` | JavaScript, JSX | 536,633 |
| `python.wasm` | Python | 566,020 |
| `typescript.wasm` | TypeScript, TSX | 2,989,379 |

Together 4.6 MB of a 96 MB binary. The budget added about 300 bytes to each
module.
