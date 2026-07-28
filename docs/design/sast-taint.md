# Deterministic Intraprocedural Taint Analysis (SAST)

Status: foundation (design + catalog + data model). The dataflow engine that
consumes this foundation depends on an AST/structural substrate built
separately; this note freezes the contract that substrate plugs into.

## Goals and constraints

Nox is deterministic, offline, pure-Go. Taint analysis must obey those same
rules: no network, no LLM, no nondeterminism. Concretely:

- **Deterministic** — the same input file always yields the same findings in the
  same order. The catalog is embedded at build time (`go:embed`); the stub
  engine sorts its output by `(sink line, source line, sink call)`.
- **Offline** — the source/sink/sanitizer knowledge is a shipped data file, not
  fetched or inferred.
- **Intraprocedural-first** — propagation is tracked *within a single function
  body* (a `Unit`). We do not follow calls into other functions in this phase.
  This is the pragmatic 80/20: most injection bugs are a source and a sink in
  the same handler. Interprocedural and cross-file flow is explicitly out of
  scope here and is where the existing `nox-plugin-taint-analysis` cross-file AI
  taint (TAINT-AI-\*) already operates; this foundation generalizes that plugin's
  source/sink/sanitizer *shape* to the classic sink classes without contradicting
  its rule IDs.
- **Language priority** — Python and JavaScript/TypeScript first. They dominate
  web-app injection surface and have the clearest, most stable dangerous-call
  vocabulary. Go is already covered structurally by the taint plugin and is not a
  priority for this catalog.

## The taint model

A **taint flow** is an untrusted value (from a **source**) reaching a dangerous
operation (a **sink**) without passing through a **sanitizer** appropriate to
that sink's vulnerability class.

```
source ──assign──▶ var ──propagate──▶ var ──▶ SINK        → finding
source ──▶ var ──▶ SANITIZER(class) ──▶ var ──▶ SINK      → no finding
```

The join key between sinks and sanitizers is the **vulnerability class**
(`VulnClass`). A sink declares its class; a sanitizer declares which classes it
neutralizes. Neutralization is class-specific on purpose: `html.escape` defuses
XSS but does nothing against command injection, so a value escaped for HTML and
then passed to `os.system` is still a finding.

Source **kind** (http_query, env, file, …) is informational — it enriches the
finding and aids triage but does not gate the join; any tainted value can in
principle reach any sink.

### Propagation (intraprocedural)

Within a `Unit` (function body presented as an ordered `[]Statement`):

1. A statement that calls a **source** and assigns a variable taints that
   variable, recording the originating `Source`.
2. A statement that reads a tainted variable and assigns another **propagates**
   taint to the assignee (assignment, string concat/format, f-strings, list/dict
   construction — the substrate decides which reads count).
3. A statement whose assignee is produced by a **sanitizer** for the relevant
   class **clears** taint (for that class).
4. A tainted variable read as an argument to a **sink** emits a flow tagged with
   the sink's `VulnClass`, `CWE`, and `RuleID`.

The full engine will additionally model branches, container-element taint, field
sensitivity, and **argument-position/keyword sensitivity** (e.g. `subprocess.run`
is only a command-injection sink with `shell=True` or a string command; a
parameterized `cursor.execute(sql, params)` is safe). Those refinements are noted
per-entry in the catalog (`note`) and are the substrate's responsibility; the
stub engine does not yet apply them.

## Sources

Untrusted-input entry points. Catalog kinds:

| Kind           | Meaning                              | Python examples                         | JS/TS examples                     |
|----------------|--------------------------------------|-----------------------------------------|------------------------------------|
| `http_query`   | URL query / path params             | `request.args`, `request.GET`           | `req.query`, `req.params`, `location.search` |
| `http_body`    | request body / form / json          | `request.form`, `request.get_json`      | `req.body`, `ctx.request.body`     |
| `http_header`  | headers / cookies                   | `request.headers`, `request.cookies`    | `req.headers`, `req.cookies`       |
| `argv`         | command-line arguments              | `sys.argv`, `argparse.ArgumentParser`   | `process.argv`                     |
| `env`          | environment variables               | `os.environ`, `os.getenv`               | `process.env`                      |
| `stdin`        | standard input                      | `input`, `sys.stdin.read`               | `process.stdin.on`                 |
| `file`         | file reads                          | `open.read`, `pathlib.Path.read_text`   | `fs.readFile`, `fs.readFileSync`   |
| `network`      | socket / remote responses           | `socket.recv`, `urllib.request.urlopen` | `socket.on`, `fetch`, `axios.get`  |
| `deserialized` | decoded external data               | `pickle.loads`, `json.loads`, `yaml.load` | `JSON.parse`                     |

## Sinks (vuln class + CWE)

| Vuln class                | CWE        | Rule ID       | Python examples                                             | JS/TS examples                                       |
|---------------------------|------------|---------------|------------------------------------------------------------|------------------------------------------------------|
| command_injection         | CWE-78     | TAINT-002     | `os.system`, `os.popen`, `subprocess.run/Popen` (shell=True) | `child_process.exec/execSync/spawn/execFile`        |
| sql_injection             | CWE-89     | TAINT-001     | `cursor.execute`, `session.execute`, `sqlalchemy.text`     | `connection.query`, `knex.raw`, `sequelize.query`    |
| code_injection            | CWE-95     | TAINT-005     | `eval`, `exec`, `compile`                                  | `eval`, `Function`, `vm.runInNewContext`, string `setTimeout` |
| unsafe_deserialization    | CWE-502    | TAINT-005     | `pickle.loads`, `yaml.load`, `marshal.loads`               | (n/a in catalog v1)                                  |
| xss                       | CWE-79     | TAINT-003     | `Markup`, `mark_safe`                                       | `.innerHTML`, `document.write`, `res.send`, `dangerouslySetInnerHTML` |
| ssti                      | CWE-1336   | TAINT-003     | `render_template_string`, `jinja2.Template`                | `handlebars.compile`                                 |
| path_traversal            | CWE-22     | TAINT-004     | `open`, `os.path.join`, `send_file`, `shutil.copy`         | `fs.readFile`, `res.sendFile`, `path.join`           |
| ssrf                      | CWE-918    | TAINT-006     | `requests.get/post`, `urllib.request.urlopen`, `httpx.get` | `axios.get`, `fetch`, `http.get`, `request`          |
| prompt_injection (LLM)    | CWE-77/200 | TAINT-AI-001/002 | `chat.completions.create`, `messages.create`, `generate_content`, `embeddings.create` | `openai.chat.completions.create`, `generateContent`, `embeddings.create` |

Rule IDs deliberately reuse the existing `nox-plugin-taint-analysis` space
(TAINT-001..006, TAINT-AI-001..003) so a future core engine's findings, the
plugin's findings, baselines, and SARIF reporters share one ID space. The
LLM-prompt sinks are the same ones the plugin already models — this foundation
does not re-invent them, it catalogs them alongside the classic sinks.

## Sanitizers (per sink class)

A sanitizer neutralizes one or more classes. Highlights:

| Sink class            | Neutralizing pattern                       | Python                                         | JS/TS                                  |
|-----------------------|--------------------------------------------|------------------------------------------------|----------------------------------------|
| command_injection     | shell quoting / arg-vector exec            | `shlex.quote`, `shlex.split` (no shell)        | `shell-quote.quote`                    |
| sql_injection         | parameterized query / escaping             | `sqlalchemy.bindparam`, `psycopg2.sql.Identifier` | `mysql.escape`, `sqlstring.escape`  |
| xss / ssti            | HTML escaping / sanitizing                 | `markupsafe.escape`, `html.escape`, `bleach.clean` | `DOMPurify.sanitize`, `escape-html`, `he.encode` |
| path_traversal        | canonicalize + prefix check / basename     | `os.path.realpath`+startswith, `secure_filename`, `os.path.basename` | `path.resolve`+startsWith, `sanitize-filename`, `path.basename` |
| unsafe_deserialization| safe loader                                | `yaml.safe_load`                               | (n/a)                                  |
| ssrf                  | URL parse + host allowlist                 | `urllib.parse.urlparse`, `ipaddress.ip_address` | `new URL`, `url.parse`               |
| all (numeric coerce)  | numeric coercion drops metacharacters      | `int`, `float`                                 | `parseInt`, `Number`                   |

Some sanitizers (canonicalize, URL parse, IP validate) are marked in the catalog
`note` as **partial** — they only neutralize when paired with a check
(`startswith` on an allowed base dir, a host allowlist). The stub engine treats
any recognized sanitizer as clearing taint conservatively; the full engine will
require the paired check before clearing.

## Data model and package layout

Package `core/taint`:

- `catalog.json` (embedded) — per-language `sources`, `sinks`, `sanitizers`.
- `VulnClass`, `SourceKind`, `Source`, `Sink`, `Sanitizer`, `Catalog` — the typed
  model. `Catalog` is loaded lazily once (`sync.Once`) and indexed for O(1)
  lookup by normalized call chain.
- Lookups: `IsSource(lang, call) bool`, `Source(lang, call)`,
  `IsSink(lang, call) (Sink, bool)`, `IsSanitizer(lang, call, class) bool`.
  TypeScript/JSX/`js`/`py` aliases normalize to the canonical language key.
- `TaintEngine` interface + `heuristicEngine` stub (`NewHeuristicEngine`).

## How the implementation plugs in

The engine seam is `TaintEngine.Analyze(Unit) []Flow`:

- `Unit` = one function body as an ordered `[]Statement`; `Statement` carries the
  assigned var, the normalized call chains it invokes, and the vars it reads.
- The **AST/structural substrate** (built separately) is responsible for turning
  source files into `Unit`s: parsing, scoping to function bodies, normalizing
  call/attribute chains to the catalog's `call` form (e.g. resolving `import
  subprocess as sp; sp.run` → `subprocess.run`), and populating `Reads`/`Assigns`
  from real def-use edges. It does **not** need to know the catalog.
- The **real engine** (`StructuralEngine`, future) implements the same
  `TaintEngine` interface over those richer statements, applying branch, alias,
  and argument-position sensitivity, and consults this package's `Catalog` for
  the source/sink/sanitizer verdicts. Swapping it in is a one-line change at the
  call site; the stub's tests become its regression target.
- A thin **adapter** (not part of this foundation) maps each `Flow` to a
  `findings.Finding` using `Sink.RuleID`, `Sink.CWE`, the `Unit` location, and a
  source→sink message — reusing the existing findings pipeline unchanged.

The stub `heuristicEngine` proves this end-to-end today with a same-scope
forward-propagation heuristic (clearly marked `TODO(sast-taint)`): it is not real
dataflow, but it exercises the catalog and interface so the contract is known-good
before the substrate lands.

## Status update: the structural engine is live (Python + JS/TS)

The substrate and real engine described above now exist:

- `core/taint/engine` — the **structural substrate** (`ExtractUnits`) and the real
  **`StructuralEngine`**. Extraction is a pure-Go, line/statement-oriented
  recognizer that runs over `core/lexctx` code regions (so strings and comments
  are never mistaken for code), segments function bodies (`def` for Python) and
  the module top level into ordered statements, recognizes assignments and bare
  calls (including multi-line calls via bracket balancing and nested calls),
  normalizes dotted call chains to catalog keys via longest-first **suffix
  matching** (`flask.request.args.get` → `request.args.get`), and records
  per-sink **argument shape** (positional arity, `shell=True`, whether taint
  lands in the first positional argument).
- The `StructuralEngine` does forward, straight-line, intraprocedural dataflow
  with **class-precise sanitization** (a value `html.escape`d is XSS-safe but
  still command-injection-tainted) and **argument-aware sink gating**
  (parameterized `cursor.execute(sql, params)` and `subprocess.run` without
  `shell=True`/with an arg vector do not fire). It reuses the stub's flow
  ordering so downstream output is stable regardless of which engine ran.
- `core/analyzers/taintflow` — the **live analyzer**. It runs the engine over
  Source artifacts and maps each un-sanitized `Flow` to a `findings.Finding`
  using `Sink.RuleID`/`Sink.CWE`, located at the sink, with source/sink/class
  metadata. It is registered in `core/scan.go` like any other analyzer.

Honest limits (unchanged from the design intent): straight-line only — no
control-flow-graph/branch merging, no alias or container-element/field
sensitivity, best-effort call-name normalization, and JS/TS scoped to the module
unit for now (Python gets per-function units). These are a measurable step up
from the stub, not a full language-semantics engine.

## Status update: same-file interprocedural flow via function summaries

The engine now joins a source in one function to a sink reached through a
locally-defined helper in the **same file**, via **function summaries** —
`StructuralEngine.AnalyzeFile([]Unit)` (the per-file entry point the
`taintflow` analyzer now calls instead of the per-`Unit` `Analyze`).

How it works, in three steps:

1. **Summarize each function.** For every parameter *i* of a locally-defined
   function, a summary records: `sinksArg(i)` — parameter *i* reaches a catalog
   sink unsanitized inside the body (carrying the sink's `VulnClass`/`RuleID`/
   `CWE`); `returnsTaintedIf(i)` — parameter *i* flows unsanitized to a `return`;
   and `sanitizesClass(i)` — the classes parameter *i* is sanitized for on the
   way. Summaries are computed by seeding each parameter as a synthetic source
   and running the **same forward pass** the intraprocedural engine uses, so
   summary semantics never diverge from intraprocedural semantics.
2. **Iterate to a bounded fixpoint** over the file's call graph, so a helper that
   returns its argument tainted composes with a caller that then sinks the result
   (a two-function chain). The lattice is monotone (taint only spreads), so
   iteration converges; it is additionally capped at the function count, so
   recursion and mutual recursion terminate deterministically.
3. **Apply summaries at call sites.** A call `helper(taintedVar)` whose summary
   `sinksArg(0)` fires emits a cross-function `Flow` (with the intermediate
   helper named in `Flow.Via`); `x = wrap(taintedVar)` whose summary
   `returnsTaintedIf(0)` fires marks `x` tainted and propagation continues.
   Argument→parameter binding is **positional**. The finding is located at the
   caller's call site and its message/metadata name the helper path
   (`via: wrap -> run`).

Honest limits of the interprocedural pass (this is exactly where the cross-file
`nox-plugin-taint-analysis` takes over):

- **Same-file only.** A callee defined in another file is an *unknown callee*: we
  never invent a sink or propagate taint through it (fail safe — no false
  positive). Cross-**file** flow stays the taint-analysis plugin's job.
- **Best-effort callee resolution.** A helper called by its bare local name (or a
  chain whose suffix is a local name) resolves; a helper reached through an
  attribute, a variable holding a function, or a decorator-rewrapped name is
  treated as unknown.
- **Bounded fixpoint.** Iteration is capped at the function count; a pathological
  graph simply stops early with the summaries computed so far (fail safe).
- **Positional binding only.** Keyword and `*args` call arguments do not bind a
  specific parameter and are conservatively ignored for summary application
  (never fabricated).
- Inherits all intraprocedural limits above (no CFG/branch merging, no alias or
  field/element sensitivity), and JS/TS remains module-scoped so its
  interprocedural benefit is limited to Python for now.

## Status update: Ruby support (line recognizer)

Ruby joins Python and JS/TS on the **lexctx line/statement recognizer** path
(pure-Go, no CGo, no tree-sitter). `core/lexctx/scan_ruby.go` classifies Ruby
code/string/comment (incl. `#{}` interpolation as code, heredocs, `%w/%q`
literals, `=begin/=end`, and regex-vs-division disambiguation);
`core/taint/engine/extract_ruby.go` recognizes `def` params, assignments,
explicit `return`, `params[:x]` hash-index sources, and — the Ruby-specific
shapes — paren-less calls (`system "..."`), backtick/`%x` command literals,
`::` scope resolution, and no-arg sink methods (`.html_safe`). The catalog's
`ruby` block adds sources/sinks/sanitizers across TAINT-001..006.

Measured on `testdata/precision-suite-ruby`: **precision 1.00 / recall 0.875 /
F1 0.933** (14 TP, 0 FP, 2 FN). The two recall gaps are honest and documented
(`render inline:` template injection — indistinguishable from auto-escaped
`render plain:` by call name; cross-method flow through an `@ivar` — outside the
local-summary interprocedural model). Ruby inherits every intraprocedural limit
above and is module/`def`-scoped like Python.

## Semantics: a partially tainted URL is still reported (SSRF, TAINT-006)

A recurring shape, found in three languages while validating the engine against
real repositories:

```elixir
[tag] = System.argv()
Req.get!("https://api.github.com/repos/elixir-lang/elixir/releases/tags/#{tag}")
```

```bash
local path="$1"
curl "${NEXUS_URL}/service/local/${path}"     # NEXUS_URL is a literal
```

```bash
curl -fSL -o "$tarball" "https://go.dev/dl/go${version}.src.tar.gz"
```

In each, an untrusted value reaches a network fetch, but the URL's **scheme and
host are literal** — only a path segment is attacker-controlled. Whether that is
CWE-918 is genuinely arguable: SSRF classically means the attacker chooses the
DESTINATION, and here they cannot redirect the request to another host.

**nox reports it.** The reasoning:

- The dataflow is real. An untrusted value does reach a URL passed to an HTTP
  client, and that is the flow the rule describes.
- Attacker control of a path segment is not nothing: `../` escapes, an injected
  `?`/`#`, or a `@` that some URL parsers read as an authority separator can all
  change what is fetched. Proving the host is fixed needs a URL-structure model
  the engine does not have.
- Silently dropping the class would trade a debatable finding for a silent miss,
  which is the wrong direction for a scanner whose whole premise is that
  degradation must be visible.

**Why this is documented rather than narrowed.** Suppressing it requires
modelling URL structure — parsing the literal prefix, deciding which
interpolation positions are authority-changing, and getting that right in every
language. That is a real feature. Measured against it: across ~14,000 real files
(Clojure, Dart, Groovy, Elixir corpora) the engine emits **8 TAINT-006 findings
in total, of which 2 are this class**. Building URL-structure analysis for two
findings is not a good trade.

What would change the decision: if a corpus sweep shows this class dominating
TAINT-006 volume, or a downstream user reports it as their top noise source,
narrow it then — and pin the corpus number here so the trade is re-checked
against evidence rather than intuition.
