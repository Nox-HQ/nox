# Metamorphic corpus

A curated, deterministic set of real-world-shaped inputs for the corpus-wide
metamorphic sweep (`scripts/metamorphic/sweep.py`). The sweep applies
semantics-preserving edits (blank lines, whitespace reflow, CRLF, inert
keyword-comments) to each file and asserts nox's finding set does not change; any
finding that appears or disappears under such an edit is a rule bug. This corpus
gives the oracle many rules to exercise across the languages and rule-families
where context-confusion bugs live.

**These files are intentionally finding-bearing** (unpinned base images, public
S3 buckets, hardcoded credentials, taint flows, script injection). They are
excluded from nox's own self-scan in `.nox.yaml`, the same way the precision
corpora are; the sweep scans them explicitly in isolated temp dirs. Do not "fix"
them — their findings are the point.

## Layout

| Directory | Files | Families exercised |
|---|---|---|
| `docker/` | 4 Dockerfiles (python service, node multistage, root installer, hardened distroless) | `IAC-0xx`/`IAC-1xx` Dockerfile rules, `CONT-001` base-image pinning |
| `workflows/` | 3 GitHub Actions workflows (mutable tags, `pull_request_target` injection, SHA-pinned release) | `IAC-012`/`IAC-013` action pinning, workflow-permission and injection rules |
| `terraform/` | 3 `.tf` files (public S3, open security groups, wildcard IAM + unencrypted RDS) | `IAC-004`/`IAC-040`/`IAC-1xx`/`IAC-3xx` Terraform rules, `SEC-2xx` field secrets |
| `python/` | 5 files (cloud secrets, SQLi, command injection, SSRF, LLM agent) | `SEC-0xx` secrets, `TAINT-0xx` taint, `AI-0xx` prompt/logging |
| `javascript/` | 2 files (cloud/Slack/Stripe secrets, XSS + command + eval sinks) | `SEC-0xx` secrets, `TAINT-0xx` taint |
| `go/` | 2 files (cloud secrets, SQLi + command injection handlers) | `SEC-0xx` secrets, `TAINT-0xx` taint |

19 files total. The `hardened` Dockerfile and the `deploy-pinned` workflow are
deliberately *clean* variants of a construct — a metamorphic oracle needs both
the vulnerable and the safe shape of a pattern to tell "precise" from "overfit".

## Coverage (rules exercised on current `main`)

The sweep reports `rules_exercised` and a full per-rule coverage map in
`triage_report.json`. As of the current corpus it exercises **37 distinct
rules** across six families (IAC-283 was retired into IAC-036 in #394, which
the corpus already exercises, so the same construct is still covered):

```
AI-002, AI-006,
CONT-001,
IAC-001, IAC-003, IAC-004, IAC-005, IAC-006, IAC-012, IAC-013, IAC-014,
IAC-024, IAC-036, IAC-037, IAC-040, IAC-121, IAC-122, IAC-123, IAC-124,
IAC-126, IAC-127, IAC-167, IAC-282, IAC-315, IAC-317, IAC-318,
SEC-001, SEC-003, SEC-023, SEC-030, SEC-080, SEC-086, SEC-508,
SLOP-001,
TAINT-001, TAINT-002, TAINT-006
```

The triage report also ranks rules that fire on exactly one distinct construct
(`single_construct`) — these are under-exercised and are the worklist for
growing the corpus: give such a rule a second, differently-shaped construct so
the sweep can cross-check its robustness.

## How to extend

1. Add a realistic file under the right family directory (small, deterministic,
   no secrets that are *real* — use well-known example/placeholder values).
2. Re-run `python3 scripts/metamorphic/sweep.py --bin ./nox --results out` and
   check `out/triage_summary.md`: confirm your file adds coverage and introduces
   no *new* verified violation.
3. If it surfaces a genuine, pre-existing rule bug (a verified violation), keep
   the file and record the violation in `scripts/metamorphic/known_issues.json`
   with a repro note, rather than deleting the construct.

Keep the corpus small enough that the full sweep stays a few minutes in CI.
