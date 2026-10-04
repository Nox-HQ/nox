# Concrete witnesses: result — decision B, investigation harness only

Measured 2026-10-04 on `64cc5f7` (v1.48.1 + #813), the binary built from that
commit. Research basis: KLEE (OSDI 2008), EXE (CCS 2006), SymCC (USENIX
Security 2020), each of which turns a path condition into a concrete input
that is then run on the real program.

> **Question:** can nox construct a concrete input on which a detector and an
> independently specified security condition disagree, and are such
> witnesses more precise at finding implementation defects than corpus
> frequency or structural deviance?
>
> **Answer: yes for the formats that can be specified, and those are few.**
> Independent references could be written for 8 credential formats covering
> 29 of 883 secret rules. They produced 640 disagreements in 35 classes, and
> every disagreement replayed through the real binary. Reading those classes
> found **4 implementation defects** and 16 smaller divergences. The defects
> are:
> - nox misses age's post-quantum identity, including the spec's own example;
> - a JWT's claim and severity depend on whether the word `jwt` appears in its file;
> - SEC-519 cannot see SNS ARNs in the `aws-cn` and `aws-us-gov` partitions;
> - the CSP/ETag construction survives in SEC-335, where any git commit SHA in
>   a file naming Sourcegraph is a high-severity credential.
>
> Deviance mining found 0 of 67 by the same standard. **The solver was not
> what found them.** Bounded enumeration over each reference's constraints
> found every class. z3 found no class enumeration had missed, and 13 of its
> 33 witnesses did not reproduce, because its model of a rule is not the rule
> nox runs.

Nothing here is wired into nox. No rule was changed. The four defects are
listed for separate fixes under the standing rule that a rule is fixed by its
claim, not removed.

## Method

```
security proposition   one per format, written down first (refs/*.go: Proposition)
→ reference predicate   refs/, a separate Go module that cannot import nox
→ actual NOX            the nox binary, on files on disk, nothing in-process
→ search                reference boundaries × detector regex paths × hosts
→ witness               any disagreement
→ replay                the witness alone, fresh tree, every scope, --offline
→ adjudication          by class, labels in adjudicate.py
```

**Independence is enforced, not promised.** `go.mod` here declares a module
that does not require `github.com/nox-hq/nox`. The references cannot call a
nox validator, reuse a nox regex or share a helper. That is why base62,
Bech32, the macaroon v2 reader and the PEM checks are rewritten here, even
where nox has its own. Every reference is tested against the examples its own
source publishes (`refs_test.go`):

- age.md's two identities;
- the IAM docs' example key ID;
- RFC 7519 §3.1's JWT, and §6.1's unsecured JWT, which must classify as
  `unsecured`;
- the SNS API reference's ARN.

A reference that rejected its own source's example would be wrong before
judging anything.

**actual(x) is always the binary.** The search scans every candidate in one
batch with `--only secrets`. The replay scans each witness alone with every
scope. They agreed on 640 of 640, so batching changed nothing. The two runs
were identical on all 1,332 candidates (deterministic, seed `20261004`).

**Candidates come from three generators:**

- **reference-valid instances**, one per published variant of the format;
- **one-constraint mutants** of each: a glued neighbour, ±1 length, a checksum
  flip, a label mismatch, a placeholder body, standard base64 for url-safe,
  truncation;
- **detector paths**: each claiming rule's regex walked to every top-level
  alternative and every quantifier at its minimum and its bound
  (`cmd/witness/regexgen.go`). This generator may read the detector because
  it only proposes inputs. The reference judges them.

**Hosts are part of the model.** Each candidate is written into the file
shapes its issuer produces, as well as into neutral ones:

- `age-keygen` output;
- `~/.aws/credentials`;
- `.pypirc`;
- a curl `Authorization: Bearer` line;
- a `.env` line;
- a YAML block scalar;
- a JSON string with `\n` escapes;
- inline Markdown.

The first run used only assignments. There, the generic entropy rule SEC-161
reported nearly everything and hid both age defects. Host choice changed the
answer.

### Two harness defects, found before any result was read

- **The claim lists were taken from patterns and missed rules.** SEC-017,
  SEC-217 and SEC-251 claim GitHub and JWT formats in their descriptions. They
  were missing, so their findings read as "another rule reported it". Claim
  lists now come from the descriptions in the built rule dump. A claim list is
  part of the model.
- **The two GitHub shapes were judged separately.** The classic and the
  stateless `ghs_` references share claiming rules, so every classic token
  failed the stateless reference with "prefix". They are now one disjunctive
  reference.

## The practical reproduction (toy/)

The toy is a 30-character token format with branches for prefix, separator,
body length, alphabet and an optional suffix. It has one deliberate defect:
`&&` for `||` in the suffix branch, which accepts a 25-character body. It also
has one plausible edge case: an uppercase prefix, which looks like a leak and
is spec-conformant, because ABNF quoted strings are case-insensitive.

| search | result |
|---|---|
| bounded enumeration over the reference's partition | 5,096 inputs in <1 ms. 12 witnesses, all the deliberate defect, 0 others |
| z3, one query for any length ≤ 40 | UNKNOWN on 3 of 4 queries at 60 s |
| z3, one query per exact length | faithful model: the defect found; FN direction **UNKNOWN at lengths 29 and 32** |
| z3, simplified model (forgets `ToLower`) | the defect found, **plus an FN witness that does not replay**: both real functions accept it |

So the lesson the intent asked for shows up twice:

- **A plausible edge case is not a witness.** The uppercase prefix looks
  suspicious, and both functions agree on it.
- **A solver result is a fact about its model.** The simplified model's
  witness disagrees only with a function nobody wrote.

UNKNOWN at two lengths also means the faithful search never proved that no FN
exists.

## The formats

### Modelled (8 formats, 29 rules)

| format | source of each constraint | rules claiming it |
|---|---|---|
| GitHub classic + stateless `ghs_` | GitHub blog (prefixes, separator); the 2026-04 changelog (legacy `ghs_` shape by example); docs.github.com (`ghs_APPID_JWT`) | SEC-003, 017, 213, 215, 216, 217, 435, 495, 496, 497 |
| AWS access key ID | IAM identifier prefixes; IAM API `AccessKeyId` 16–128, `[\w]+` | SEC-001, 508, 509 |
| Twilio API Key SID | Twilio glossary: 34 chars, 2-letter prefix + 32 hex, SK = API Key | SEC-057 |
| SNS topic ARN | ARN reference (3 partitions); CreateTopic (name grammar) | SEC-519 |
| age identity | C2SP age.md; BIP-173 | SEC-077 |
| PyPI token | pypi.org/help; warehouse issuer code; libmacaroons `format.txt` | SEC-046, 302, 409, 503 |
| signed JWT | RFC 7515 §2–3, RFC 7519 §6, §7.1 | SEC-084, 251, 371 |
| PEM private key | RFC 7468 §2, §10, §11; RFC 5915; RFC 8017 A.1.2; OpenSSH `PROTOCOL.key` | SEC-004, 299, 390, 391, 426, 427 |

**What was deliberately left out, and why:**

- **GitHub's checksum.** GitHub documents that a CRC32 Base62 checksum
  exists. It does not document whether the prefix is hashed or the digit
  order, and no real revoked token was found to settle either. A checksum
  written from inference would be a guess dressed as a specification.
- **AWS's base32 alphabet.** Every real key uses it, but AWS was not found to
  say so. The reference is therefore exactly as loose as AWS's documentation,
  and that looseness is itself a result (below).

### Not independently modelable

| format | rules | why |
|---|---|---|
| npm | SEC-045, 282, 408, 502 | prefix and "CRC32 in Base62" documented; length, alphabet and checksum input not |
| GitHub fine-grained | SEC-016, 214 | prefix only |
| GitLab | SEC-018, 132, 225, 226, 436 | prefixes documented; lengths not; the routable format exists only in a design doc that contradicts itself |
| Slack | SEC-023, 024, 025, 323–332, 437, 498, 499 | prefixes documented; Slack reserves up to 255 characters and documents no body |
| Stripe, Databricks | SEC-438, 015, … | researched: prefixes documented, body by a single example at most |
| Hugging Face, Anthropic, Google API key, SendGrid, Shopify, Square, Doppler, Postman | 30+ | **not researched exhaustively**: no primary format source surfaced beyond a prefix |
| Google `ya29.`, Facebook `EAAC`, Bedrock `ABSK` (credential-body audit) | SEC-423, 424, 199, 169 | no published body: the audit's question cannot be settled by a model. That justifies a human looking. It is not evidence the rules are wrong |
| Twilio Account SID | SEC-379 | the format is documented, but the question is whether a username-role identifier is a credential. That is a proposition, not a format |
| RSA private exponent (SEC-161, 162) | — | **refused** (below) |

Of the **14 formats whose primary sources were researched, 8 could be
modelled honestly**. Those 8 cover 29 of 883 rules. The other 6 publish a
prefix and little else. Five more groups are unmodelable by their nature: the
three credential-body prefixes, the Account SID proposition and the RSA
exponent. Eight vendor families were not researched in depth. Most vendors do
not publish their formats.

## Measurements

| | |
|---|---:|
| rules modelled | 29 (8 formats) |
| formats researched and not independently modelable | 6 of 14 (+5 unmodelable by nature, 8 not researched) |
| candidates generated | 1,332 |
| disagreements (counterexamples) | 640 = 494 FP, 124 FN, 22 claim-gap |
| **replayed successfully** | **640 / 640** |
| disagreement classes | 35 |
| implementation defects | **4 classes** (+1 from the HTTP sweep), 4 distinct defects |
| divergences, low or unestablished consequence | 16 classes |
| legitimate intentional differences | 8 classes |
| reference-model mistakes | **4 classes, 164 witnesses (26%)** |
| unresolved by the source | 3 classes |
| reference code | ~1,200 lines (`refs/`), of which PEM 248 and PyPI + JWT ~200 |
| time to witness | 9 s for the full search and every replay; z3 1.9–24 s per SAT query |

The key denominator is replayed witnesses, and here it does not discriminate:
everything replays, because `actual` *is* the binary. **The denominator that
does discriminate is classes after adjudication.** 4 of 35 are defects. If
divergences count as implementation departures, 20 of 35 are. 4 of 35 are
the reference's own mistakes, and they hold a quarter of all witnesses. Raw
witness counts measure the generator. Forty strings failing one Bech32
checksum are one fact.

`claim-gap` was not in the intent's taxonomy. It arose because the scanner,
unlike any single rule, reports some valid credentials under a rule that does
not claim them. One of the four defects is in that column.

## The four defects

**1. age's post-quantum identity is not reported.** The C2SP age spec defines
an ML-KEM768-X25519 identity with HRP `AGE-SECRET-KEY-PQ-` and publishes an
example. That example, replayed:

- in an `age-keygen`-shaped keys file: **no finding**;
- in `export SOPS_AGE_KEY=…`: SEC-161 only, medium, "high-entropy string";
- the classic example beside it: SEC-077, **critical**.

SEC-077's pattern hard-codes the `-1` separator immediately after
`AGE-SECRET-KEY`. The format changed after the rule was written. *Class:
fn/pq-hybrid-unreported and claim-gap/pq-hybrid-only-generic.*

**2. A JWT's claim depends on a variable name.** The same signed JWT gives:

| how it is written | what nox reports |
|---|---|
| `jwt_value = "…"` | SEC-371, **high**, "Detected JWT token" |
| `value = "…"` | SEC-161, **medium**, "High-entropy string in assignment" |
| in prose | SEC-084, medium |

The mechanism is in `core/analyzers/secrets/dedup.go`, `resolveOwners`:

- The prefix table gives `eyJ` to SEC-371.
- SEC-371's file keyword is `jwt`, so with no such word it never fires.
- With the generic SEC-161 as the anchor, pass 1 drops every non-owner
  provider finding on the span (SEC-084, SEC-251) whether or not an owner is
  present.
- The guard "only once at least one true owner is present … so we never
  suppress the last finding on a real secret" protects the anchor and not the
  findings it drops.

The ledger records SEC-084 deferring to "canonical rule SEC-161". This
contradicts the file's own invariant that generic entropy rules "are the least
specific — always losers". It applies to any owned prefix whose owner can be
absent. *Class: claim-gap/generic-entropy-wins-dedup.*

**3. SEC-519 cannot see two of the three documented partitions.** The pattern
is the literal `arn:aws:sns:`. ARNs in `aws-cn` and `aws-us-gov` are never
reported, even in a file that contains the rule's keyword. The solver
reproduced this independently: 12 of 12 z3 FN witnesses replay. Severity is
info, so the consequence is small. It is still a straightforward gap.
*Class: fn/partition-unreported.*

**4. The CSP/ETag construction survives in SEC-335.** The HTTP sweep wrote
four kinds of value beside each of 736 vendor names, in six shapes (8,832
files):

- RFC 9110 entity-tags;
- CSP Level 3 hash-sources;
- W3C traceparents;
- RFC 9562 request IDs.

The v1.35.0 shape (a CSP naming the vendor, an ETag below it) produced
exactly one vendor-rule finding: SEC-335, "Sourcegraph". Its pattern has a
bare `[a-fA-F0-9]{40}` alternative gated only by the file keyword
`sourcegraph`. That is the pre-v1.36 construction in a gitleaks import the
v1.36 fix did not reach. Forty hex digits is also a git object name, so the
consequence is broad:

- a README that says "we index with Sourcegraph" and pins a commit: **high**
  finding;
- a workflow line `uses: actions/checkout@<sha> # sourcegraph indexer`:
  **high** finding, on the SHA pinning that supply-chain guidance recommends.

The alternative presumably exists for legacy unprefixed Sourcegraph tokens;
that was not verified. The fix is to bind that form to a Sourcegraph binding,
not to drop it.

**And the fix that worked.** For the other 735 vendor names, in the shape
that caused the original incident, there were no vendor-rule findings. That is
direct confirmation that the v1.36 binding holds family-wide.

## The divergences and the rest

- **Missing token boundaries (7 classes).** SEC-057, 017, 215, 216, 217, 508,
  509 and SEC-084 report a span inside a longer alphanumeric run, such as
  `TASK<32 hex>`, `x` glued to a token, or a 37-character `ghp_` run. Their
  siblings for the same format (SEC-001, 003, 435) are `\b`-bounded, so this
  is inconsistency within a family, not design. No realistic input was
  constructed for most of them, so the consequence is unestablished.
- **age checksum not validated.** `AGE-SECRET-KEY-1` followed by 58 zeros is a
  **critical** finding, and its Bech32 checksum cannot verify. Unlike GitHub's
  checksum, BIP-173 documents this one completely. nox already treats GitHub
  checksum verification as deterministic evidence. The same evidence is
  available for age and unused.
- **Placeholder handling is inconsistent across formats.** An all-zero AWS
  body is dropped. All-zero age and GitHub bodies (the latter found by z3) are
  reported.
- **The sources' own examples, replayed.** The IAM documentation's example
  access key ID (the one ending in `EXAMPLE`) is reported at **high**:
  - in `~/.aws/credentials`, **twice**, by SEC-001 and SEC-508;
  - in `value = "…"`, once.

  The placeholder refiner does not recognise the most-published example key
  there is. The dedup prefix table names both rules as owners of `AKIA`, so
  neither yields. Whether a documentation example should be reported is a
  policy question. Two findings for one token is not.

  Separately, writing this harness, BIP-173's published Bech32 charset
  constant was reported by SEC-161 as a possible secret.
- **RFC-valid JWT shapes.** A pretty-printed header, whitespace before the
  claims, or empty claims (`{}`) produce no finding in prose. The rules assume
  compact JSON (`eyJ`), which RFC 7519 §7.1 explicitly does not require.
  Prevalence is low.
- **Intentional (8 classes).** Regex rules do not decode PyPI macaroons,
  JWT JSON or PEM DER. A truncated token or half a key is still reported,
  which is defensible: partial key material leaks. A curl `Authorization`
  line belongs to the Bearer rules.
- **Reference-model mistakes (4 classes, 164 witnesses).**
  - PEM: I required the END label to match. RFC 7468 says parsers *MAY*
    disregard it, and the body is real key material, so nox is right. Same for
    a missing END line. The reference modelled the format where the
    proposition is about the material.
  - JWT and Twilio: a valid token followed by `=` or `!` was judged as a whole
    string. Those characters are delimiters, so the reported span *is* the
    token.
  - AWS: 103 FN witnesses are keys the documentation allows and no issuer has
    produced: lowercase bodies, digits 0/1/8/9, lengths other than 20. SEC-001
    encodes the base32 shape every real key has. **The reference was honest to
    its source, and its source is too loose to judge the rule.**
- **Unresolved (3 classes).**
  - SEC-001's `A3T` prefix: AWS does not document it and says "prefixes may
    vary".
  - SEC-251 reporting unsigned JWTs: RFC 7519 says such a token is not a
    credential. Whether it belongs in a scanner is a proposition question.
  - SEC-519's `aws_sns` keyword gate: ARNs elsewhere go unreported. That
    might be intended scoping to Terraform.

## SMT against nox

`nox_smt.py` hand-translates three rules into z3 regexes and asks, per exact
length, for model-versus-reference disagreement. Each witness is then
replayed:

| rule | direction | SAT | replayed | why not |
|---|---|---:|---:|---|
| SEC-003 | FP | 5 | 5 | — (one is an all-zero body nox reports as a GitHub PAT) |
| SEC-003 | FN | 1 | **0** | the `ghr_` witness is reported by SEC-217: a per-rule model cannot see the scanner |
| SEC-057 | FP | 3 | 3 | but 2 are reference mistakes (`!` is a delimiter) |
| SEC-519 | FP | 12 | **0** | the translation omitted the `aws_sns` keyword pre-filter; nox never ran the rule |
| SEC-519 | FN | 12 | 12 | partitions, defect 3 |

**20 of 33 replay, 18 are informative, and 0 are in a class enumeration had
not already found.** The solver's power went into satisfying constraints a
boundary enumerator states directly. What it could not see was everything
around the regex: keywords, other rules, dedup and refiners. Those are
exactly where two of the four defects live.

## The required falsification cases

- **RSA private key (SEC-161/162).** Refused. No authoritative source says a
  high-entropy assignment *is* an RSA private exponent, and the earlier
  corpus vetoed narrowing the rule. A reference written anyway would encode
  "entropy means private key", the assumption this research exists to avoid.
  The PEM reference does the opposite. It parses the DER, so the claim it
  makes is about the bytes.
- **CSP/ETag.** Modelled through the values instead of the credential: an
  entity-tag is RFC 9110's "opaque validator", not a credential, whichever
  vendor is named nearby. The result is defect 4, plus confirmation of the
  v1.36 fix across 735 names. The SEC-161 witnesses (202, every one on a line
  where my host placed a credential-like word) are labelled intentional. That
  heuristic qualifies a value by any keyword on its line. Measured with the
  word in a description field, it still fires.
- **AI-029 / AI-041.** Not modelled, and unexplained by this method. Their
  question is whether a configuration choice belongs in a security scanner. A
  format model has nothing to say about it. Symbolic agreement with a
  formalisation would show only that the detector implements the
  formalisation.
- **Credential-body audit.** Google `ya29.`, Facebook `EAAC` and Bedrock have
  no published body. Failing to model them is recorded as exactly that. It
  does not imply the prefix-only rules are wrong, and it does not license
  narrowing them.

## Model limitations

- **Bounded strings.** The toy is ≤ 40 ASCII characters. The nox SMT uses
  exact lengths 33–51. z3 strings are code points while Go strings are bytes,
  so non-ASCII input is out of scope.
- **Regex semantics.** The z3 translations ignore `\b`, flags and keyword
  pre-filters. The enumerator ignores empty-width assertions and draws only
  printable ASCII.
- **Tokenisation.** References judge the whole candidate, which made `=` and
  `!` look like part of a token (counted above as reference mistakes).
- **Sources.** The PyPI serialisation is issuer code, not documentation.
  OpenSSH's armour label is code only. RSA PRIVATE KEY is OpenSSL convention.
  GitHub's `ghs_` APPID is assumed to be decimal. Twilio hex case is
  undocumented, so both cases are accepted. The SDK-only AWS partitions
  (`aws-iso*`, `aws-eusc`) are excluded.
- **Environment.** `--offline`. 15 globally installed plugins did not run,
  because they are not in `plugins.required`, so the replay is core nox. Key
  material comes from a seeded RNG: structurally valid, never real.

## Decision gate: B

**Not A.** Routine format-constrained rule testing would need routine
independent formats. Of 14 formats whose sources were researched, 6 have
none, and the 8 that do cover 3% of the catalogue. A quarter of the witnesses were the reference's
own mistakes, and labelling them took reading RFCs and nox's dedup code. Both
format defects came from **sources that changed after the rule was written**
(age added PQ identities; GitHub's `ghs_` became stateless). Noticing that is
re-reading vendor documentation, not running a tool. And the solver, the part
that would make this "tooling", found nothing that enumeration missed.

**Not C.** The references were independent: the module boundary made
anything else impossible. They found four replayed, adjudicated defects that
the prevalence, independence and structural-majority approaches did not, at a
class precision (4/35 defects, 20/35 departures) that deviance mining's 0/67
does not approach. They also confirmed a past fix family-wide, which no
corpus can, because a corpus cannot contain the inputs nobody has written yet.

**B.** The harness stays here as an investigation tool. Run it when:

- a rule is written for a format that has a published specification;
- a vendor changes a format;
- a fix needs its witness turned into a regression fixture.

No rule-review signal, score, gate or automatic change follows from it.

> Concrete witnesses beat inferred suspicion where a format is published. A
> published format is the exception, and the published format had moved on
> from the rule in both of the format defects found.

## Reproducing

```bash
go build -o /tmp/nox ./cli
NOX_RULE_DUMP=/tmp/rules.json go test ./core/analyzers/secrets -run TestDumpRuleSet
cd docs/research/concrete-witnesses
go test ./...                                   # references vs their sources; the toy
python3 toy/solve.py per-length > toy/witnesses.json && go test ./toy -run Replay -v
go run ./cmd/witness    -nox /tmp/nox -rules /tmp/rules.json -out /tmp/cw
go run ./cmd/httpvalues -nox /tmp/nox -rules /tmp/rules.json -out /tmp/cwh
python3 nox_smt.py /tmp/nox /tmp/cws
python3 adjudicate.py /tmp/cw/outcomes.json /tmp/cwh/httpvalues.json /tmp/cws/smt_witnesses.json > measurements.json
```

`measurements.json` identifies witnesses by sha256 only. Every input is
credential-shaped by construction, and the seeded harness regenerates them.

## Addendum, same day: the defects, fixed and re-measured

Every defect and divergence this research adjudicated was fixed by its claim,
with no rule removed. Each fix was reviewed independently on built binaries and
merged:

| PR | Fix |
|---|---|
| #816 | SEC-077 covers age's post-quantum and lowercase identities; Bech32 checksum recorded as evidence only |
| #817 | SEC-519 covers every partition, matches only real ARNs, keyed on `:sns:` (the `aws_sns` gate was an import artefact) |
| #822 | the 11 sibling ARN rules, same construction, per-service ARN shapes |
| #815 | SEC-335 binds legacy 40-hex Sourcegraph tokens; SHAs and ETags no longer report |
| #818 | dedup: only provider-tier findings decide ownership |
| #819 | SEC-371 runs on every JWT; a JWT's severity no longer depends on the word `jwt` |
| #820 | SEC-251 requires a signature (RFC 7519 §6), so unsigned JWTs are not credentials |
| #821 | a rule's trailing lookahead stand-in is excluded from the span; dedup compares multi-line spans by position |

Two of these came from fixing, not from the harness:
- **#820** answered the "unresolved" unsigned-JWT class.
- **#821** came up while fixing #819. 135 rules' spans swallowed the delimiter after the token, which hid duplicates from dedup.

**Re-run on `2f2aaed`**, the same harness and seed, classes compared:

| class | before | after |
|---|---:|---:|
| age PQ unreported / generic-only | 2 / 2 | 0 / 0 |
| age lowercase unreported / generic-only | 4 / 4 | 0 / 0 |
| SNS partition unreported | 4 | 0 |
| SNS keyword gate | 2 | 0 |
| unsigned JWT reported | 24 | 0 |
| compact JWT reported only by generic SEC-161 | 7 | **0** |

Two classes did not reach zero, and neither is a defect:
- **The `generic-entropy-wins-dedup` bucket still holds 6 witnesses.** They are
  the RFC-valid JWT shapes no JWT rule matches: a pretty-printed header,
  whitespace before the claims, and empty claims. The adjudicator's classifier
  files them in the same bucket as the dedup defect. That divergence is
  unchanged and still open.
- **SNS has 2 `aws-eusc` ARNs.** #817 deliberately includes the SDK-only
  partitions; this reference follows the IAM docs.

Class sizes elsewhere moved for expected reasons:
- Lowercase age identities now match, so more checksum-invalid lowercase samples
  report. The checksum is evidence, not a gate.
- Three claiming rules changed pattern, so the seeded detector-path generator
  proposes different candidates (1,362, previously 1,332).

**Still open:**
- the RFC-valid JWT shapes above;
- whether published example tokens (jwt.io) should be suppressed;
- whether public-by-design tokens (Supabase anon keys) belong in a secrets
  scanner.
