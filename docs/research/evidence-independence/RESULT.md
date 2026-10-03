# Evidence independence: result — decision B, keep as research tooling

Measured 2026-10-03. Research basis: Le Goues & Weimer, *Specification Mining
with Few False Positives* (TACAS 2009), and Ammons, Bodík & Larus, *Mining
Specifications* (POPL 2002). Both get their precision from counting
observations that really are independent. This asks whether nox's corpus can
supply that count.

> **Question:** how much independent evidence is behind an empirical
> observation count?
>
> **Answer:** an upper bound on it, plus a bracket that is too wide to publish
> as one number. Four reasonable definitions of an authored occurrence give
> counts that differ by 2× or more on 6 of the 33 rules with at least 10
> findings, and up to 9×. Two definitions that agree on a count can still
> disagree on which findings they merged. Independence depends on how the
> corpus was designed, so nox does not expose it as a metric.

The shipped tier 2 (`by_site`: path with locale and version segments removed)
stays exactly as it is. This work found what it is: the **most conservative**
of the measured collapses, an upper bound on the independent count. It is not
an estimate of it.

## What was run

The seven repositories of `docs/benchmarks/2026-09-15`, at their pinned
commits, scanned offline with two builds:

- `77314c3`, the commit that benchmark names. It still ships the withdrawn
  AI-022, AI-029 and AI-041, so the adjudicated cases are present.
- `HEAD` (`5f86aa1`, v1.47.0).

Two more scans cover the adjudicated cases that are not in that corpus:

- certbot at its rule-diff pin, for the RSA private-exponent case.
- crewAI's `tests/cassettes` subtree with **v1.35.0**, for the CSP/ETag and
  vendor-keyword cassette failures. These were fixed before `77314c3`, so they
  only reproduce on the older binary.

**Reproduction check first.** The published bench was a "scratch build". 101 of
its 115 rules reproduce exactly, counting both raw findings and sites. The 14
that differ are vendor rules that `77314c3` itself retired or bound, plus AI-029
on vercel/ai's `__fixtures__`. SEC-583 on the v1.35.0 cassettes reproduces the
6,160 recorded in `scripts/rule-diff-corpus.json` exactly.

`independence.py` maps every raw finding to a unit under each model. Each unit
keeps the raw finding refs it absorbed, so nothing that is collapsed loses its
provenance. `measurements.json` holds the per-rule, per-model results for all
four scans.

| Model | Unit |
|---|---|
| M0 raw | one finding |
| M1 exact line | rule + whitespace-normalised matched line(s), corpus-wide |
| M1 window | rule + matched lines ±3, corpus-wide |
| M2 path site | rule + repo + path without locale/version segments + line (**shipped tier 2**) |
| M2 file copy | rule + whole-file content hash + line |
| M2 authored | transitive union of path site, file copy and window |
| M3 repo | rule + repository |
| M4 family | rule + declared family (the openai and anthropic SDKs are both Stainless-generated) |

Material class (recorded / generated / test / docs / example / source) is a
**label** on each unit. It is never a weight.

## AI-031 ablation

| Step | Units | Top repo (share) | Effective repos |
|---|---:|---|---:|
| raw findings | 260 | crewAI (0.94) | 1.13 |
| exact-line collapse | 16 | vercel/ai (0.63) | 2.25 |
| context-window collapse | 19 | vercel/ai (0.63) | 2.21 |
| path site (shipped) | 20 | vercel/ai (0.60) | 2.35 |
| file-copy collapse | 22 | vercel/ai (0.55) | 2.55 |
| authored union | 18 | vercel/ai (0.67) | 2.05 |
| repository | 4 | — (0.25) | 4.00 |
| family | 4 | — (0.25) | 4.00 |

Material: 249 of the 260 raw findings are crewAI documentation. After collapse,
crewAI holds **2 to 4** units depending on the model. The finding recorded in
`rule-review-candidates.md`, "AI-031 is 244→4 on crewAI alone", holds up. Its
conclusion turns over once the collapse is applied: crewAI is no longer the
concentrated repository. After collapse vercel/ai holds 12 of roughly 19 units.
Raw concentration measured copies of crewAI's docs, not where the rule fires.

The models agree on the size of the AI-031 collapse (16 to 22 units). They do
not agree on the reason. Path site merges translations of a page, because
`docs/edge/ko/…` and `docs/v1.10.0/en/…` normalise to the same path. The
context window keeps translations apart, because the prose around the code
differs by language, and merges only identical version copies. A union that
takes both gives 2 crewAI units, fewer than either model alone.

## The eight questions

**1. The smallest defensible unit.** No single unit works for every finding
type, because a finding's location is not always its evidence.

- For line-located pattern findings, the path site is defensible as an upper
  bound.
- For file-located findings it is wrong. VULN-002 reports at line 1 of a
  lockfile, so the context window hashed `version = 1` and merged unrelated
  vulnerabilities, including **three different repositories' `uv.lock` into
  one unit**. VULN-002 swings 9× across models (54 by path, 6 by content).
- The defensible unit for a dependency finding is its subject (package,
  version, advisory). That is tier 3, and tier 3 is declared, not derived
  (`docs/design/condition-dedup.md`).

**2. Is the repository enough, or do project families matter?** Families
matter, but only at **file** granularity.

- In this corpus the openai and anthropic SDKs are one generator family. They
  share generated `_compat.py` and `_models.py`, which gives 2 real
  cross-repository SLOP-001 units.
- Declaring the family at repository level merges findings in **11 rules**.
  For 10 of them the merged findings share no content: SEC-161 in one SDK's
  hand-written tests is not the same evidence as SEC-161 in the other's.
- A family is therefore not a corpus attribute. It is authored-source identity
  again, at a coarser grain.
- Across the whole corpus, content matching finds only 3 cross-repository
  units: the 2 SLOP-001 units, and the VULN-002 lockfile-header merge, which is
  false.

**3. How to represent generated, versioned and docs material.** As a label,
derived from paths, and the derivation is fragile:

- **It depends on the scan root.** Cassettes copied to the root of a scan lose
  the `/cassettes/` segment and classify as source.
- **Every heuristic needed a hand fix.** certbot's `certbot_integration_tests/`
  and vercel/ai's `__fixtures__/` were classified as source until the patterns
  were widened.
- **The class does not predict validity.** The RSA private key that SEC-161
  must keep finding lives in a test asset. The `authorization:` header that
  makes cassettes worth scanning is recorded material.

So a material class can describe findings. It must never discount them.

**4. Can authored-source identity be derived reliably?** Not reliably.

- The three content- and path-based derivations make different merges.
- The merge decision encodes a view of authorship that reasonable people
  dispute. Example: SEC-082's `authorization: 'Bearer test-api-key'` is pasted
  into 8 provider test files in vercel/ai. Content collapse makes that 1 unit,
  path makes it 8. Both readings are defensible, because a template copied by
  hand is neither one decision nor eight.
- The evidence spine already settled this for itself: `IndependentSources()`
  counts a **declared** `Provenance.SourceID`. It never infers one. Corpus
  findings carry no source identity, and deriving it is exactly the step that
  fails here.

**5. Does duplicate collapse change prevalence materially?** Yes, by a lot:

| Corpus | Raw | Path site | Window | Authored union | Repo-level |
|---|---:|---:|---:|---:|---:|
| seven repos, `77314c3` | 4,252 | 3,097 | 2,420 | 2,407 | 221 |
| seven repos, HEAD | 1,440 | 1,155 | 1,031 | 1,021 | 186 |
| crewAI cassettes, v1.35.0 | 7,312 | 676 | 539 | 539 | 22 |

Most of the collapse at `77314c3` has since been removed by fixing rules, not
by counting differently. HEAD's raw total is a third of `77314c3`'s, and its
raw-to-authored ratio fell from 1.77 to 1.41.

**6. Do reasonable independence models disagree strongly?** Yes, on both the
size of the count and its content.

- Across the four authored-level models, 8 of 33 rules disagree by at least
  1.5× and 6 by at least 2×. In order: VULN-002 9.0×, AI-035 3.2×, AI-022
  2.8×, AI-034 2.7×, AI-041 2.4×, AI-036 2.2×.
- Equal counts can still be different partitions. DATA-001 gives 26 units under
  both the path-site and window models, but 17–27% of the merged pairs differ.
  For AI-036, path site and window share **none** of the merges the window
  model makes.
- Kendall τ ranks rules by count under each model. Between the authored-level
  models τ is 0.75–1.00, which is fine for ranking. Against repository count it
  falls to 0.25.

**7. Can independence be measured without a hidden quality judgement?** Only
for the conservative case.

- Dropping locale and version path segments encodes no claim about whether a
  line matters.
- Every step past that does encode one. That covers merging copied test
  templates, discounting tests or recordings, and merging a generator family.
  Each step is a statement about which evidence counts.

**8. Is repository concentration still useful after normalisation?** It
measures something different, and that something depends on the unit.

- The dominant repository **changes** under normalisation for 6 rules: AI-031,
  DATA-001, AI-022, SEC-162, SEC-801 and SEC-803.
- Concentration can also **rise**. AI-029 goes from 0.57 to 0.94 and SEC-803
  from 0.68 to 0.90, once crewAI's documentation copies stop diluting vercel/ai.
- Raw concentration is a measurement of the corpus. Normalised concentration
  is a measurement of the corpus seen through one model. Neither is a property
  of the rule. This settles items 1 and 2 of the "No repository-concentration
  bar" note in `docs/design/rule-review-candidates.md`. They have no
  corpus-independent answer, and the bar stays unbuilt.

## Retrospective falsification

The hypothesis predicts that independence exposes inflation **without**
tracking validity. Every adjudicated case fits that prediction:

| Case | Adjudication | Raw → authored | What independence says |
|---|---|---|---|
| RSA private exponent (certbot JWK, SEC-161) | **valid**, must keep | 7 → **1** | one unit, correctly |
| SEC-583 Zuora on a base64 PDF (cassettes) | **false positive**, fixed | 6,160 → **1** | one unit, correctly |
| SEC-446 Cloudflare cookies (cassettes) | **false positive**, fixed | 188 → **110** across 69 files | highly "independent" |
| CSP/ETag: one ETag, five vendor rules | **false positive**, fixed | 5 rules × 1 span | **invisible**: the multiplication is across rules, not within one |
| AI-029 | **withdrawn**, not a security proposition | 199 → 65 | moderate |
| AI-041 | **withdrawn** | 33 → 14 (path site: 33) | models disagree 2.4× |
| AI-022 | **withdrawn** | 292 → 34 | the same shape as… |
| AI-031 | **live** | 260 → 18 | …this |
| vendor pairs (25 B-group rules) | merge rejected: unique spellings | **24 of 25 have zero units** | no evidence either way |

The most useful pair is the first two rows. **A real private key and a
keyword accident in a PDF each collapse to exactly one independent unit.** The
count is right both times, and it carries no information about which is real.

SEC-446 shows the other direction: 110 independent false positives. AI-022
(withdrawn) and AI-031 (live) have the same collapse profile. The vendor-pair
decision rested on constructed inputs, because the corpus has no evidence for
24 of the 25 rules.

The ETag case is a reminder that the multiplication that misled people was
**cross-rule**. That is condition identity (`condition-dedup.md`), and no
per-rule independence model can see it.

## Decision gate: B

Option A needed "N raw findings represent approximately M independent corpus
observations", defined reproducibly. The measurement does not support
"approximately" at a useful width:

- Brackets of 2–9× on a fifth of the frequently firing rules.
- Different partitions behind equal counts.
- A family dimension that is wrong at the only grain a corpus manifest can
  easily declare.
- Material labels that change with the scan root.

So:

- **Not exposed** as a nox metric or as bench metadata. No "independent
  observations" column, weight, or bracket.
- **`by_site` stays as shipped.** It is now documented as an upper bound on
  independence, never as an estimate of it.
- **The tooling stays here**, and every unit keeps its provenance to raw
  findings, for the next time a corpus number has to be read.

**What would reopen this:** a corpus manifest that **declares** source identity
(generated paths, vendored trees, generator families at file grain), the same
way tier 3 declares subjects. That would match the evidence spine's rule:
independence is counted over declared sources and never inferred from
observations. The open question is whether such declarations can be written
and maintained for a corpus. This result does not answer it.

## Not built, deliberately

No bad-rule score, no retirement or narrowing, no combined review score, no
concentration gate, and no weighting formula. The table above is the reason for
each: the one property independence measures well, whether repetition is
inflation, says nothing about whether a rule is right.

## Reproducing

```bash
# clone each repo in docs/benchmarks/2026-09-15/bench.json at its commit into corpus/<owner>-<repo>
for d in corpus/*/; do n=$(basename $d)
  nox scan $d --output out/$n --quiet --offline </dev/null; done
python3 docs/research/evidence-independence/independence.py out corpus res
# res.table.json: per-rule, per-model units / top repo / share / material
# res.provenance.json: every unit with the raw findings it absorbed
```
