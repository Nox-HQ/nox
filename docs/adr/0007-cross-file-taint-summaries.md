# ADR 0007: Cross-file taint through function summaries, reported at the sink

- Status: Accepted
- Date: 2026-11-22
- Deciders: nox maintainers
- Extends: the same-file summaries in `core/taint/engine/interproc.go`

## Context

The taint engine joins a source in one function to a sink in another only
when both are in the same file. Its own documentation names the limit, "a
callee defined in another file is an unknown callee", and hands cross-file
flow to the taint-analysis plugin, which has since been archived as a
regression. The commonest injection shape in a real application crosses a
file: a handler reads the request and calls a service or a DAO in another
module, and the DAO builds the query.

Measured on the RealVuln development split after the tree-sitter front ends
(the held-out split stays sealed for the gate), of the 749 missed labels in a
taint class (SQL, command, path, SSRF, XSS, code, XPath, LDAP, template,
deserialization, redirect) in Python, JavaScript/TypeScript and Java:

| what stands between the label and a finding | labels |
|---|---:|
| no catalog sink recognised near the label | 334 |
| a sink, whose operand is not a parameter of its function | 227 |
| a sink reached by a parameter of its function | 100 |
| a sink at module scope | 81 |
| no line in the label | 7 |

The third row is what cross-file summaries address: the function already
hands a parameter to a sink, and a caller in another file passing a source in
would complete the flow. It is spread across 60-odd repositories, 63 of the
100 in Java and 30 in TypeScript. The second row is mostly the next task
(route handlers' parameters as sources wherever they are defined); the first
is catalog coverage.

Two facts make the change cheaper than it looks. `core/callgraph`'s
`SourceBuilder` already resolves calls across files for every language the
extractor reads (relative JavaScript imports, dotted Python modules, Java
classes by file stem, dependencies kept apart from project code), and it
already holds every file's units for the scan. And the same-file engine
already computes, for every function, which parameter reaches which sink
unsanitized, which it returns, and which it sanitizes for.

Where such a finding is reported was decided separately (plan, M1,
"interprocedural finding location", moved here on 2026-11-22): at the sink
inside the helper, with the call path as evidence, the fingerprint change
made once, with cross-file summaries. A finding at the call site points a
reader at a line that does nothing dangerous, and a benchmark labels the
sink.

## Decision

1. **Resolution is the call graph's.** A call binds to a function in another
   file only as `SourceBuilder` binds it: one candidate or none. Two
   candidates, a method on a value of unknown type, a function value, a
   framework callback: the callee stays unknown, and an unknown callee
   contributes nothing, as it does today. No second resolver is written.
2. **Summaries per file, a bounded fixpoint across files.** Each file's
   summaries are computed by the existing engine, with the summaries of the
   other-file callees its calls resolve to supplied as fixed inputs. Files are
   iterated in path order until no summary changes, at most 4 rounds; the
   lattice is monotone (taint only spreads), so a stop at the bound is
   incomplete, never wrong. Only same-language edges are followed.
3. **The cross-file pass only adds.** It reports a flow only when its path
   crosses a file. It never refutes a finding the per-file pass made, and a
   file it cannot resolve is analysed exactly as before.
4. **Reported at the sink.** An interprocedural flow -- same-file or
   cross-file -- is reported at the sink statement inside the function that
   reaches it, in that function's file. The call path, caller first with
   each step's file and line, is the evidence (`flow_path`). One finding per
   sink and rule, carrying every path that reaches it: each caller that hands
   a source to the sink is a separate injection point, so `flow_paths` lists
   them all (the first, in a deterministic order, is `flow_path`) and
   `flow_path_count` counts them. A cross-file caller of a sink a same-file
   caller already reaches adds its path to that finding instead of a second
   one. A source read in another file (a getter resolved across files) is
   named with its file (`source_file`), since its line is that file's.
5. **A real source supersedes a parameter.** A parameter-SQL finding
   (`paramSQLFlows`, low confidence: no source in the file) at a sink a
   source now reaches through a resolved call is replaced by the sourced
   flow.

## Consequences

- Measured on the RealVuln development split (A/B of built binaries over one
  pinned tree): F3 15.6 -> 16.5 (Java 7.0 -> 8.0, JavaScript/TypeScript
  21.5 -> 23.0, Python 23.2 -> 23.1). Cross-file flows: +33 labelled, +70
  unlabelled. Same-file flows moved to the sink: +12 labelled where the label
  is at the sink, -5 where it is at the call site (vfapi's four handlers
  into one `run_sql_query`, pygoat's `command_out`); those call sites stay on
  the finding as its paths.
- Fingerprints of existing same-file interprocedural findings change once,
  because their location moves from the call site to the sink. The rule-diff
  ledger records it in the PR that makes the change.
- Memory: none new; the builder already holds the units. Time: a second
  forward pass over only the units whose calls resolve to another file's
  function with a non-empty summary.
- Deterministic: path order, a bounded fixpoint over a monotone lattice, and
  the existing flow ordering.
- Limits, stated on the rules: same-language only; positional argument
  binding only; dispatch through an interface with more than one
  implementation, a value whose type the file does not declare, or a
  function value is unresolved.
- Amended 2026-11-23 (route entry points across files): a call on a field,
  parameter or variable binds through the type the file declares it with
  (`private final StaffService directory;`, `constructor(private readonly
  svc: FetchService)`, `self.repo = UserRepository()`) to that type's method
  in the one file declaring the type, or, for an interface or abstract type,
  to its one subtype that has the method. A name declared with two types, a
  type two files declare, or two implementations bind to nothing. This is
  how a Spring or NestJS controller reaches the service it is injected with;
  it is still the call graph's resolution (decision 1), one candidate or
  none. An enhanced `for (T x : items)` header is now a statement, `x =
  items`, so a call made there is a call of the method. Measured on the
  development split (both binaries rescanned at low load): F3 16.5 -> 17.0,
  +28 labelled, none lost, +38 unlabelled, mostly existing sink matches the
  flows now reach (a class's own `exec` method read as a shell, a
  `PrintWriter` on an SSH channel read as a response); one wrong edge
  removed, where a field typed `PortalAuditService auditService` had bound to
  another module's `AuditService.java` by its stem.
