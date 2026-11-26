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

## C#, PHP, Ruby and Kotlin (2026-11-26)

Four more grammars, pinned in `scripts/treesitter/pins.json`: C#
(`tree-sitter-c-sharp` v0.24.0), PHP (`tree-sitter-php` v0.25.2, the `php`
grammar rather than `php_only`: a real file opens with `<?php` and may hold
HTML around it, which `php_only` does not parse), Ruby (`tree-sitter-ruby`
v0.23.1) and Kotlin (`tree-sitter-grammars/tree-sitter-kotlin` v1.1.0, the
grammars-org repository, which is the one with a 2025 release; `fwcd`'s last
release is from 2024). A second `build.sh --check` rebuilt every module and
licence byte-equal.

Modules, the runtime included in each:

| Module | Languages | Bytes |
|---|---|---:|
| `csharp.wasm` | C# | 7,387,033 |
| `kotlin.wasm` | Kotlin | 3,588,588 |
| `ruby.wasm` | Ruby | 2,235,477 |
| `php.wasm` | PHP | 1,187,068 |

That is 14.4 MB more in the binary, on top of the 4.6 MB above: 19.0 MB of
tree-sitter in total. C# alone is 7.4 MB, because its grammar's parse tables
are large; it is the one to drop first if binary size ever has to give. The
first C# parse in a process also pays for compiling that module, about half a
second on the measuring machine; the other three compile faster.

Measured on every `.cs`, `.php`, `.rb`, `.kt` and `.kts` file in 27 pinned
public repositories (see
`docs/plans/2026-11-deterministic-lead.md`, M3), including vendored
code, with the same harness and on a machine at a load average of 40 to 60, so
the throughput is indicative and the checks are exact:

| Language | Files | MiB | MiB/s | Checks/KiB p50 | p99 | max | Most checks, one file | Error trees |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C# | 11,244 | 34.1 | 0.26 | 8.9 | 15.2 | 22.6 | 2,827 | 12 |
| Kotlin | 4,018 | 17.1 | 0.33 | 7.2 | 11.9 | 25.0 | 600 | 152 |
| PHP | 13,354 | 78.1 | 0.75 | 6.8 | 14.3 | 20.2 | 3,146 | 6 |
| Ruby | 8,939 | 21.9 | 0.49 | 10.4 | 14.4 | 21.2 | 7,683 | 2 |

Checks per KiB are over files of at least 1 KiB. No file exceeded
`DefaultBudget` (2,000 checks plus 64 per KiB): the costliest used 19% of its
budget in PHP, 19% in Ruby, 18% in C# and 10% in Kotlin. Kotlin gives an error
tree for 3.8% of files (152 of 4,018, most of them in JetBrains/Exposed); the
front end falls back to the line segmenter on those, as on any error tree.

## Scala, Swift, Rust and C/C++ (2026-11-26)

Four more grammars, pinned in `scripts/treesitter/pins.json`: Scala
(`tree-sitter/tree-sitter-scala` v0.26.14), Swift (`alex-pinkus/tree-sitter-swift`
0.7.4, the `-with-generated-files` tag, because the plain tag ships no
`parser.c`), Rust (`tree-sitter/tree-sitter-rust` v0.24.2) and C/C++
(`tree-sitter/tree-sitter-cpp` v0.23.4). One grammar parses both C and C++: nox
has one language for the two (`lexctx.LangCPP`), and `tree-sitter-c` was not
built or measured. `build.sh --check` rebuilt all twelve modules and licences
byte-equal; the eight earlier modules are unchanged.

Modules, the runtime included in each:

| Module | Languages | Bytes |
|---|---|---:|
| `scala.wasm` | Scala | 4,743,656 |
| `swift.wasm` | Swift | 4,348,185 |
| `cpp.wasm` | C, C++ | 3,563,969 |
| `rust.wasm` | Rust | 1,244,394 |

That is 13.9 MB more in the binary, on top of the 19.0 MB above: 32.9 MB of
tree-sitter in total, 12 modules. Scala and Swift are the two near 5 MB; none
is over it. The unstripped `nox` binary went from 111 MB (after C#, PHP, Ruby
and Kotlin) to 125 MB.

The Swift scanner calls `exit(1)` when its one allocation fails, so
`swift.wasm` also imports WASI `proc_exit`. The host provides it as a stub that
ends the guest: the call that reached it fails and the file falls back like any
other trap. `TestModulesImportOnlyTheStubbedFunctions` names that one
exception.

Measured on every `.scala`/`.sc`, `.swift`, `.rs` and `.c`/`.h`/`.cc`/`.cpp`/
`.cxx`/`.hpp` file of at most 2 MiB in 30 pinned public repositories (see
`docs/plans/2026-11-deterministic-lead.md`, M3), vendored code included, with
the same harness and a machine at a load average of 160 to 250, so the
throughput is indicative and the checks are exact:

| Language | Files | MiB | MiB/s | Checks/KiB p50 | p99 | max | Most checks, one file | Error trees |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Scala | 3,999 | 18.6 | 0.20 | 7.9 | 13.2 | 20.6 | 2,550 | 4 (0.1%) |
| Swift | 3,895 | 41.6 | 0.13 | 7.2 | 13.8 | 17.2 | 5,136 | 317 (8.1%) |
| Rust | 5,875 | 51.2 | 0.11 | 7.5 | 13.7 | 20.0 | 2,495 | 537 (9.1%) |
| C/C++ | 4,902 | 63.5 | 0.14 | 6.4 | 15.2 | 32.0 | 5,385 | 2,335 (47.6%) |

Checks per KiB are over files of at least 1 KiB. No file exceeded
`DefaultBudget` (2,000 checks plus 64 per KiB): the costliest used 16% of its
budget in Scala, 20% in Swift, 19% in Rust and 25% in C/C++ (a generated CRC
table in redis). A file that gives an error tree falls back to the line
segmenter, as on any error tree. Where the error trees are:

- **Rust, 537:** 526 are in `cargo`'s test suite, which writes expected output
  as `str![[r#"..."#]]`, a raw string inside a macro token tree that the grammar
  does not parse. The other 11 are in diesel (4), sqlx (3) and nushell (4).
- **Swift, 317:** Signal-iOS 237, fluent-kit 42, vapor 20, GRDB 15. Four
  sampled Signal files stopped at `@available(iOS 17, *)` before a declaration,
  at a trailing-closure argument label (`footer: {`), and at missing tokens
  inside async closures; the fluent-kit and vapor files were not inspected.
- **C/C++, 2,335:** 1,956 of 3,500 `.c` files (56%) and 366 of 1,255 `.h` files
  (29%), against 6 of 139 `.cpp` files (4%). A preprocessor conditional between
  `if` and `else` (`#ifdef AF_INET6` in curl) and an unknown macro in a
  declaration (busybox, 696 of 751 files; curl's `CS_ENTRY(...)` tables) are
  the causes sampled. The C++ grammar parses C with a preprocessor it does not
  model; whether `tree-sitter-c` does better on `.c` files was not measured.
