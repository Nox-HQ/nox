# Go taint model — AST-precise extraction

Status: implemented. Companion to [`sast-taint.md`](./sast-taint.md), which
describes the language-agnostic engine (catalog + `StructuralEngine` +
same-file interprocedural summaries). This document explains the ONE thing Go
does differently from Python and JavaScript: how source is turned into the
engine's IR.

## Why Go uses `go/ast` while Python/JS use the line recognizer

The Python and JavaScript extractors (`extract_python.go`, `extract_javascript.go`)
deliberately avoid a real parser. Nox ships a single static, CGo-free binary and
refuses to take on a tree-sitter grammar (CGo) or a large pure-Go grammar port
for those languages; instead they lean on `core/lexctx` to see only real code and
recognize the two statement shapes (`lhs = expr`, `callee(args)`) that carry the
overwhelming majority of injection bugs. That is a pragmatic precision/cost trade.

Go is different, and the difference is free:

- **Nox is itself a Go program.** `go/parser`, `go/ast`, and `go/token` are in the
  standard library the binary already links. There is no new dependency, no CGo,
  and no module-graph cost — the constraint that rules out tree-sitter for the
  other languages simply does not apply.
- **A real AST is strictly more precise** than a line recognizer: selector chains,
  nested calls, receivers, `if`/`for` init statements, and multi-return assignments
  are parsed exactly rather than approximated by bracket-depth heuristics. Line and
  column come from `token.FileSet`, so findings anchor on the real sink line.
- **It stays deterministic and offline.** Parsing is a pure function of the bytes;
  the walk is in source order; no map iteration escapes into output.

So the rule is: **use the best tool that is already free.** For Go that is the
stdlib AST. For Python/JS it remains the lexctx line recognizer, because a real
grammar there would violate the no-CGo / no-heavy-dependency constraint. Tree-sitter
remains refused for the non-Go languages.

## What the extractor produces

`extractGo` walks each `*ast.FuncDecl` and emits one `unitDraft` per function
(receiver + parameters become `params`, in order, for the interprocedural summary
pass). Package-level `var` declarations and `init` bodies fold into a synthetic
module unit. For each statement it emits the same internal IR the other extractors
do (`stmtDraft{assigns, calls, reads, chains, sinkArgs, returns}`), so the shared
`StructuralEngine` and the same-file interprocedural fixpoint run **unchanged**.

Statement shapes handled: `*ast.AssignStmt` (`:=` and `=`, including multi-value
`a, err := f()`), bare `*ast.ExprStmt` calls, `*ast.ReturnStmt`, and the init
clause of `*ast.IfStmt`/`*ast.ForStmt`/`*ast.SwitchStmt` (so
`if err := decoder.Decode(&v); err != nil` is analyzed).

### Call-chain rendering

Selector and call expressions are rendered into the same **dotted chain** string
the catalog and `recognize.go` match against, dropping call parentheses:
`r.URL.Query().Get(id)` renders to `r.URL.Query.Get`, and the engine's
`suffixKeys` fallback matches the catalog's canonical `URL.Query.Get`. Nested
calls (a call in an argument, a call as a method receiver) are all emitted, so
`exec.Command("sh","-c","x "+name).Output()` yields both `exec.Command` and
`.Output`, and the tainted argument evidence is recorded against `exec.Command`.

### Package-qualified vs method-suffix sinks (the precision trade)

Go sinks come in two shapes and the catalog holds both:

- **Package-qualified** — `exec.Command`, `os.ReadFile`, `http.Get`,
  `gob.NewDecoder`, `template.Parse`. Here the selector's `X` is an imported
  package, so the full chain is a precise, low-ambiguity key. These are matched on
  the full dotted form.
- **Method-on-a-value** — `db.Query`, `conn.Query`, `tx.Exec`, `.Decode`. The
  receiver *name* varies (`db`, `conn`, `tx`), so the catalog keys the **method
  suffix** (`.Query`, `.Exec`, `.QueryContext`, `.Decode`) and the engine's
  `suffixKeys` matches any receiver. This is deliberately less specific: a
  same-named method on an unrelated type can match (e.g. some non-SQL `.Query`).
  The cost is bounded because (a) a flow only fires when a *tainted* value reaches
  the call, and (b) SQL sinks apply the parameterized-query argument gate
  (tainted value only in a non-first positional arg ⇒ safe), which suppresses the
  common safe form. We accept a small potential over-match on method-suffix sinks
  in exchange for covering the receiver-name-varies idiom that dominates real Go
  database and decoder code. Package-qualified sinks carry no such ambiguity.

### The inline-source hoist (deserialization)

The shared engine taints a **variable** on assignment from a source; it has no
path for a source used inline as a sink argument in the same statement. Go's
`gob.NewDecoder(r.Body).Decode(&env)` is exactly that shape: the source `r.Body`
is an argument to the sink call, never assigned. To keep the engine unchanged, the
Go extractor **hoists a pure selector chain used as a call argument** (idents and
dots only — `r.Body`, `r.URL`; never a call, operator, or literal) into a
synthetic assignment `__noxsrcN = r.Body` immediately before the statement, and
rewrites the argument to read the temp. The engine then taints `__noxsrcN` iff the
chain is a catalog source, and the taint flows into the sink on the next line. The
hoist is catalog-independent and semantics-preserving (a pure selector has no side
effects), so it is inert on non-source chains and adds no false positives — the
clean stressors, which contain no request-attribute chains, are untouched.

## Scope and honest limits (AST-only, no `go/types`)

The extractor is **AST-only**: it never loads packages or runs `go/types`. Type
resolution needs a full build context (all imports resolvable, build tags, GOOS),
which is heavy, network/filesystem-sensitive, and non-deterministic across
environments — the opposite of what a fast, offline scanner wants. The
consequences, inherited on top of the engine's existing intraprocedural /
same-file limits:

- **No type-based sink disambiguation.** `.Query`/`.Exec`/`.Decode` match by
  method name, not by proving the receiver is a `*sql.DB` or `*gob.Decoder` (see
  the method-suffix trade above).
- **Import aliases are resolved lexically, not semantically.** `exec.Command`
  matches whether or not `os/exec` was aliased, because matching is on the dotted
  chain suffix; a package imported under a *different* local name than its suffix
  (rare) would be missed.
- **Inherited from the engine:** intraprocedural + same-file interprocedural only,
  straight-line (no CFG/branch merging), no alias analysis. Container taint is
  tracked at the **container level** (see below), not per key/element.

### XSS-to-response sinks (reflected XSS, CWE-79)

Tainted request data written as HTML to an `http.ResponseWriter` fires `TAINT-003`
(xss). The sinks, all AST-recognized on the call-chain suffix:

- `fmt.Fprintf` / `fmt.Fprint` / `fmt.Fprintln` and `io.WriteString` — the first
  argument is the writer; a tainted value among the args is reflected content. No
  literal gate: a tainted string reaching a string-writer IS reflected output.
- `w.Write([]byte("<b>"+user+"</b>"))` — a raw byte write. This one **is** gated
  on a co-located string **literal** in the write argument (the reflected-HTML
  concat shape). A bare `w.Write(out)` of a precomputed value — e.g. command or
  file output — is *not* reflected XSS (that value is already reported at its own
  upstream sink), so it does not fire. This gate is what stops the injection
  samples (all of which end in `w.Write(out)`) from double-firing an XSS false
  positive. It lives in `extract_go.go` (`isGoRawWriteSink` / `xssWriteArgIsHTML`),
  keeping the change Go-local.
- `template.HTML(tainted)` — the `html/template` **auto-escape bypass**. Converting
  a tainted string to `template.HTML` marks it as trusted HTML, so contextual
  escaping is skipped and it reaches the response unescaped. Modeled as an
  unconditional sink.

Crucially, safe `html/template` interpolation (`tmpl.Execute(w, structData)`) is
**not** a sink: `Execute`/`ExecuteTemplate` auto-escape their inputs, so the
guardrail `clean_html_autoescape.go` stays clean. Only the raw-write paths and the
`template.HTML` bypass are sinks.

### Container-level taint (index / field / element)

An assignment whose LHS is an index (`m["c"] = v`), selector (`obj.Field = v`),
star, or paren target attributes taint to the **base identifier** (`m`, `obj`), so
a tainted RHS taints the whole container (`lhsAssignedName` in `extract_go.go`).
A later read of any element of that container is then treated as tainted, so
`m["c"] = user; exec.Command("sh","-c", m["c"])` fires. This is a sound
over-approximation at the **container level, not the key level**: writing one key
taints the container, so a read of a *different, clean* key of the same container
is also treated as tainted. Key/element-level precision would tighten this at some
risk to recall and is not modeled. The change is Go-local (`extract_go.go` only);
the shared `StructuralEngine` is untouched, and per-class sanitizer clearing still
holds (a value sanitized into a local before the field write stays clean, so
`clean_field_safe.go` fires nothing).

### Vuln classes covered / not covered

Covered (fire on the precision corpus): command injection (`exec.Command`),
SQL injection (`.Query`/`.Exec` concatenation), path traversal
(`os.ReadFile`/`os.Open`), SSRF (`http.Get`/`http.Post`), unsafe deserialization
(`gob.NewDecoder`, `yaml.Unmarshal`), SSTI (`text/template` `.Parse`), reflected
XSS-to-response (`fmt.Fprintf`/`w.Write`/`template.HTML`; see above), and
container-level taint through maps / slices / struct fields (see above).

Not yet covered (honest): key/element-level container precision (only
container-level today), type-based confirmation that a `.Write`/`.Query` receiver
is the expected type (AST-only, matched by method name), taint laundered through
`fmt.Sprintf` into a struct then sunk across statements, cross-file flow (the
taint-analysis plugin's territory), and reflection-based sinks.
