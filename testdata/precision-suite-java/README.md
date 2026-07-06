# SAST precision suite — Java (honest measurement corpus)

This is the Java sibling of `testdata/precision-suite/` (Python / JS / Go). It
measures nox's **Java** taint support against ground truth — what a *correct*
scanner should do — so real false positives and false negatives surface as a
number. It lives in its own directory (and gates on its own `baseline.json`) so
the Java samples and their ratchet are independent of the multi-language suite.

Java support is the lexctx line/statement recognizer (no CGo, no tree-sitter),
exactly like Python/JS: a pure-Go lexer (`core/lexctx/scan_java.go`) exposes only
real CODE (never strings/comments/text-blocks), the extractor
(`core/taint/engine/extract_java.go`) recognizes method declarations,
assignments, bare calls and returns, and the shared `StructuralEngine` runs the
dataflow **unchanged**. Sources/sinks/sanitizers come from the `java` block of
`core/taint/data/catalog.json`.

Run it:

```
nox bench --precision testdata/precision-suite-java
nox bench --precision testdata/precision-suite-java --json
nox bench --precision testdata/precision-suite-java --baseline testdata/precision-suite-java/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.java`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise that
  broad rules trip on — a base64 data-URI in a Java text block, an SRI integrity
  hash, a git SHA, placeholder/example credentials, a `@Generated` /
  `DO NOT EDIT` banner, descriptor byte constants, and safe
  (parameterized / sanitized) code.
- **True-positive samples** (`tp_*.java`) annotate the rule a correct scanner
  *should* fire, on the exact line (`// nox-expect: <RuleID>`). Firing *more*
  scores as a false positive; firing *nothing* scores as a false negative.

## Measured result

As of writing, `nox bench --precision testdata/precision-suite-java` scores
**precision 1.00 / recall 1.00 / F1 1.00** (6 TP, 0 FP, 0 FN),
findings-per-issue **1.00**, noise ratio **0.00**. Every annotated Java
vulnerability fires as its `TAINT-00x` rule and no clean stressor produces a
finding. Committed as `baseline.json`; `TestPrecisionSuiteBaselineJava` (in
`cli/`) and the `SAST precision gate — java` CI step fail if precision/recall/F1
drops or FP / findings-per-issue rises.

Note this suite scores a perfect 1.00 today because it was built alongside the
engine that catches it — the honest signal is what happens *next*: the "still
open" section below names the flow shapes a line recognizer cannot reach, and the
day one of those gets a `tp_*.java` sample the number will drop and tell the
truth, exactly as the Go suite's recall dipped to 0.79 when realistic Go samples
first landed.

## What fires (true positives)

| File | Vulnerability | Java sink (sample) | Rule | CWE |
| --- | --- | --- | --- | --- |
| `tp_cmdinjection.java` | Command injection | `Runtime.getRuntime().exec("… " + name)` | TAINT-002 | CWE-78 |
| `tp_sqlinjection.java` | SQL injection | `stmt.executeQuery("… '" + id + "'")` | TAINT-001 | CWE-89 |
| `tp_pathtraversal.java` | Path traversal | `new File("/…/" + path)` | TAINT-004 | CWE-22 |
| `tp_ssrf.java` | SSRF | `new URL(target).openStream()` | TAINT-006 | CWE-918 |
| `tp_deserialization.java` | Unsafe deserialization | `ois.readObject()` (from `request.getInputStream()`) | TAINT-005 | CWE-502 |
| `tp_xss.java` | Reflected XSS | `response.getWriter().println("… " + msg)` | TAINT-003 | CWE-79 |

Sources are the Servlet API (`request.getParameter` / `getHeader` /
`getQueryString` / `getParameterValues` / `getInputStream` / `getReader`) plus
`System.getenv` / `getProperty`. Sanitizers that keep the `clean_*` files clean:
`PreparedStatement` (parameterized `?` query), `Integer.parseInt` /
`Long.parseLong` (numeric coercion), `StringEscapeUtils.escapeHtml4` and OWASP
`Encoder.forHtml` (XSS), `FilenameUtils.getName` and `Path.normalize` (traversal).

## Sink-matching trade (documented honesty)

Two sink shapes are matched, via the engine's `suffixKeys` fallback:

1. **Package/class-qualified** calls match on the full dotted chain the flat
   recognizer produces: `Files.readAllBytes`, `ObjectInputStream.readObject`,
   `ScriptEngine.eval`.
2. **Methods on a value whose receiver name varies** match on the **method-name
   suffix**: `.executeQuery` / `.execute` / `.executeUpdate` (JDBC `Statement`),
   `.exec` (`Runtime.getRuntime().exec`), `.openStream` / `.openConnection`
   (`new URL(u)…`), `.println` / `.print` / `.write` (servlet response writer),
   `.readObject`, `.eval`.

Method-suffix matching is **AST-blind on purpose**: it does not prove the
receiver's type, so a `.executeQuery` on a non-JDBC object, or a `.println` to a
non-HTTP stream, would also match. This is the same precision trade Go's method
sinks make (see `docs/design/go-taint.md`). It is why the fluent-receiver sinks
key on the *fetch/execute* method rather than the constructor — e.g. only
`.openStream`/`.openConnection` are SSRF sinks, **not** the `URL` constructor, so
`new URL(u).openStream()` reports the flow **once**, not twice.

## Still open (honest false negatives a line recognizer cannot reach)

These are real gaps — the next indictment when a `tp_*.java` sample lands:

- **Fluent chains split across statements through untracked types.** Taint
  laundered through a builder or wrapper the flat recognizer does not follow
  (e.g. `new StringBuilder().append(user).toString()` into a sink, or a
  `HttpClient.send(request, …)` where the tainted URL is buried in a `request`
  object built earlier) is missed — there is no field/alias sensitivity.
- **Method-suffix sinks with no stable name.** `HttpClient.send` is intentionally
  *not* catalogued: `send` is too generic to key on without receiver-type proof,
  so a `java.net.http` SSRF via `client.send(...)` is a false negative rather
  than a false positive on every unrelated `.send`.
- **Cross-method / cross-file flow beyond same-file summaries.** A source in one
  method and a sink in another with no direct call between them is not joined;
  cross-file Java flow is the taint-analysis plugin's territory.
- **Control-flow / container sensitivity.** No branch merging, no loop modeling,
  no taint through maps/lists/arrays or object fields — the same limits the
  Python/JS line recognizer has.
- **`char`/text-block edge lexing.** The lexer treats a whole text block as one
  string region; it does not model the Java 15 incidental-whitespace stripping,
  which is irrelevant to code/string classification but noted for completeness.

Grow this corpus over time; the honest way to raise the number is to fix the
rules or extend the extractor the corpus indicts, **not** to curate the samples
to pass. When a fix legitimately improves the score,
`TestPrecisionSuiteBaselineJava` tells you to refresh `baseline.json`.
