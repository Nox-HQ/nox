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
   each step's file and line, is the evidence. One finding per sink and
   rule: several callers reaching one sink are one defect, and the first
   path in a deterministic order is the one shown.
5. **A real source supersedes a parameter.** A parameter-SQL finding
   (`paramSQLFlows`, low confidence: no source in the file) at a sink a
   source now reaches through a resolved call is replaced by the sourced
   flow.

## Consequences

- Fingerprints of existing same-file interprocedural findings change once,
  because their location moves from the call site to the sink. The rule-diff
  ledger records it in the PR that makes the change.
- Memory: none new; the builder already holds the units. Time: a second
  forward pass over only the units whose calls resolve to another file's
  function with a non-empty summary.
- Deterministic: path order, a bounded fixpoint over a monotone lattice, and
  the existing flow ordering.
- Limits, stated on the rules: same-language only; positional argument
  binding only; dispatch through an interface, a dependency-injected field of
  a type the graph cannot name, or a function value is unresolved. Java's
  Spring injection is the largest of these and is the route-entry-point
  task's to address, not this one's.
