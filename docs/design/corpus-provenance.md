# Declared corpus provenance

> **nox may reason from provenance that is declared. It must not manufacture
> provenance from correlation.**
>
> **Where a finding is displayed is not necessarily where its evidence came
> from.**

A corpus manifest can state where parts of a scanned tree came from:
`src/openai/types/` is generated, `docs/v1.10.0/` is a released version of a
doc set, `src/anthropic/_vendor/httpx_aiohttp/` was copied from an upstream
project. nox parses each declaration, validates it, checks it against the tree,
carries it into the bench report and shows it there. **It does nothing else
with it.**

A declaration is a supplied fact. An independence estimate built on top of
declarations would be an interpretation, and those two layers stay separate.

## Why only declared

`docs/research/evidence-independence/RESULT.md` tried to infer, from the
findings themselves, how many independent observations a raw count represents.
It could not do so reproducibly:

- **The models disagreed.** Four reasonable collapse models disagreed by 2× or
  more on 6 of 33 frequently firing rules, and by up to 9×. Equal counts hid
  different partitions.
- **A finding's location was not its evidence.** VULN-002 reports at line 1 of
  a lockfile. Hashing that location merged three repositories' `uv.lock` files,
  and their unrelated advisories, into one unit.
- **Repository-level families merged unrelated evidence.** Declaring a family at
  repository level merged 10 rules' findings that share no content.
- **True and false findings collapsed identically.** A real RSA private key and
  a keyword accident in a base64 PDF each reduce to exactly one unit.

The research also made the inference this design forbids, without noticing it
at the time. It called openai-python and anthropic-sdk-python "one Stainless
generator family". At the commits it scanned, they are Castiron (1,668 file
headers) and Stainless (4). At the autocorpus refs, both are Stainless. The
generator relationship is a property of a pinned tree, not of a project.
Checking it is what turned it from a guess into a declaration.

## The manifest

```yaml
version: 1
projects:
  openai--openai-python:            # corpus directory name
    - path: src/openai/types/       # trailing "/" = directory, claims every file under it
      provenance:
        kind: generated
        upstream: https://storage.googleapis.com/stainless-sdk-openapi-specs/openai-….yml
        basis: 'every file carries "File generated from our OpenAPI spec by Stainless"'
```

```bash
nox bench --autocorpus --provenance docs/benchmarks/corpus-provenance.yaml
nox bench --corpus <dir> --provenance docs/benchmarks/2026-09-15/provenance.yaml
```

| Kind | Origin field | Found in |
|---|---|---|
| `generated` | exactly one of `source` (an in-tree spec) or `upstream` | openai-python and anthropic-sdk-python: every file under `src/<pkg>/{resources,types}/` |
| `versioned` | `source`: the canonical copy in this tree | crewAI: `docs/docs.json` declares 39 versions matching its 39 `docs/<version>/` directories |
| `vendored` | `upstream`: the project it was copied from | anthropic-sdk-python at the 2026-09-15 pin: `_vendor/httpx_aiohttp/` headers say "Vendored from httpx-aiohttp v0.2.0 … verbatim" |

**Each kind exists because a pinned corpus tree needed it.** Two candidates
were left out deliberately:

- `translated`: crewAI declares four languages but no source language, so a
  translation's origin would be a guess.
- `mirrored`: nothing in any corpus needs it.

Adding a kind is adding a claim nox makes about the world, and needs the same
backing.

**`basis` is required, and it is the field that separates a declaration from an
inference.** A basis is where the project itself says so. For example, both
SDKs have a directory called `_vendor/httpx_aiohttp`. Only anthropic's
declares itself vendored, so only anthropic's is declared. The directory name is
not a basis.

## Validation

**Structure is checked at load.** A manifest fails, and every problem in it is
listed, when it has:

- an unsupported kind;
- a missing basis;
- the wrong origin field for its kind;
- an absolute, escaping, unclean or backslashed path;
- a source equal to or overlapping its own path;
- two declarations that overlap;
- an unknown field, such as a misspelt `upstrem:`;
- a schema version other than 1.

**The tree is checked before any scan.** Every declared path and every in-tree
source must exist, as a file or as a directory as spelt. A project the corpus
does not contain is an error, because otherwise a typo would silently drop
every declaration under it.

**What the tree check does not do: it proves a declaration names real paths,
not that the declaration is true.** At the 2026-09-15 pin, only 153 of 162 files
under openai-python's `resources/` are generated, and a `generated` claim on
the directory would still pass existence checks. That manifest therefore does
not make the claim. The truth of a declaration is the declarant's
responsibility, recorded in `basis`. Checking it by inspecting files would be
inferring provenance, which is the thing this design exists to avoid.

## Zero effect, enforced

The same corpus with and without a manifest gives identical results on every
measure below, and each is enforced by a test in
`cli/bench_corpus_provenance_test.go`:

- **Scans:** each scan receives byte-identical arguments, and a declaration
  never reaches one.
- **Counts:** findings, rule counts, prevalence and sites are identical.
- **Downstream readers:** rule-review (`--json` and `--all`) and calibrate
  output is byte-identical.
- **Exit codes:** identical.
- **Markdown:** identical, except for one added *Declared provenance* section.

`TestCorpusProvenanceHasOneReader` fails if any Go file besides the bench
report refers to the declarations. A second reader is the point where a
declaration starts to affect something, and that is a design change to argue,
not a refactor.

Each guard was checked by breaking it on purpose. Each of these sabotages
failed the build:

- declarations dropping a rule from the counts;
- declarations reaching the scan;
- declarations annotating another section of the report;
- a second file mentioning them;
- validating after scanning instead of before.

An end-to-end run of the built binary on the two SDKs at their autocorpus refs
(16 and 15 findings) produced reports identical apart from the declarations,
and byte-identical rule-review and calibrate output.

Not built, on purpose: an independence score, an independent-finding count, a
repository-concentration score, automatic collapse, evidence weighting, a rule
ranking, a rule-review signal, or a gate.

## `by_site` keeps its meaning

`by_site` is the most conservative of the measured collapses: the path with its
locale and version segments removed. **It is an upper bound on independent
evidence, not an estimate of it.** Its code comments and the bench report's own
text now say so.

## Finding location is not evidence location

A finding has a **presentation location**: where nox shows it. Its evidence has
a **subject** and an **evidence location**: what established the proposition.
VULN-002 is the measured case. Its presentation location is a lockfile header,
while its subject is a package, a version and an advisory.

Findings are not refactored for this. The requirement is carried into the
evidence-native programme as its own feature, *Evidence binds to its subject,
not to where a finding is shown* (`docs/backlog.md`):

- evidence binds to its actual subject;
- its provenance is explicit;
- the presentation location carries no identity role.

## Reopening independence research

Reopen only once enough provenance is **declared**, for example:

- generated path → declared source path;
- vendored tree → declared upstream;
- versioned copy → declared canonical source;
- fixture → declared generator.

The question then is: *given declared provenance, can nox compute useful
descriptive evidence-group views?* That is a different question from inferring
provenance from findings, and it starts from these declarations rather than
replacing them.
