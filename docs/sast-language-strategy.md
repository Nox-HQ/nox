# Per-language SAST depth strategy

nox targets roughly fifteen languages, but it does **not** invest equal
static-analysis depth in all of them. This document explains *why* the depth is
uneven, how to configure it in `.nox.yaml`, and how each depth level maps to
scanner behavior — today and as the SAST engine grows.

## Depth where the moat is

Security tooling has finite engineering attention. Spreading it evenly across
every language produces mediocre coverage everywhere and a defensible advantage
nowhere. nox concentrates depth where it pays off:

- **Python and JavaScript/TypeScript get `deep`.** This is where AI applications
  are built — LLM orchestration, prompt construction, agent frameworks, MCP
  servers and clients — so it is where nox's AI-security rules matter most. It is
  also where the pattern rules generate the **worst false positives** (dynamic
  string building, template literals, notebook-style code), so it is the first
  place richer analysis earns its keep. These languages are the moat; they get
  the deepest analysis and are the first targets for future AST/taint work.

- **Everything else gets `standard`.** Go, Rust, Java, Ruby, C/C++, C#, PHP,
  Kotlin, Swift, shell, and friends receive solid pattern-based coverage. This
  is the sensible default: real coverage without over-investing where the
  marginal security return is lower.

- **A repo can turn any language `off`.** A Go-only backend that vendors a
  handful of generated JS assets, or a Python service with a throwaway `scripts/`
  tree in another language, can silence a language it does not care to scan.
  `off` means those source files contribute **no findings** at all.

## Configuration

The strategy lives under `scan.sast.languages` in `.nox.yaml`. Keys are
language names; values are one of `deep`, `standard`, or `off`:

```yaml
scan:
  sast:
    languages:
      python: deep
      javascript: deep
      typescript: deep
      go: standard
      rust: off
      # any language not listed uses its default (see below)
```

**Defaults.** You do not need to list a language to get sensible behavior:

| Language                         | Default depth |
| -------------------------------- | ------------- |
| `python`, `javascript`, `typescript` | `deep`    |
| every other language             | `standard`    |

So the block above is equivalent to listing only the overrides you care about
(`rust: off`); `python`/`javascript`/`typescript` are already `deep` and `go` is
already `standard` by default.

**Validation.** An unknown depth value fails the scan immediately with a clear
error rather than silently defaulting — a misconfigured `off` that quietly kept
scanning (or a typo'd `deep`) would be a silent security surprise:

```
scan.sast.languages: invalid depth "shallow" for "go" (want deep|standard|off)
```

Language names are matched case-insensitively (`Python` and `python` are the
same). Unknown *language* names are not an error — they simply never match a
source file — but their depth value must still be valid.

## How depth maps to behavior

| Depth      | Behavior today                                   | Intended future behavior                          |
| ---------- | ------------------------------------------------ | ------------------------------------------------- |
| `deep`     | Current pattern-based rule analysis              | Pattern rules **plus** AST / taint / dataflow     |
| `standard` | Current pattern-based rule analysis              | Pattern rules only                                |
| `off`      | Source files of the language are **skipped** — no analyzer sees them, so they produce zero findings | Unchanged: still skipped |

### `deep` and `standard` are identical *today* — on purpose

Be honest about the current state: `deep` and `standard` run **exactly the same
analysis right now** (the existing pattern rules). The value shipped today is the
*config surface* and the *`off` skip*, not a behavioral split between deep and
standard.

Why ship the distinction before the behavior exists? Because it gives the future
AST/taint work a stable home. When deeper analysis lands, it switches on for
languages already marked `deep` with **no config migration** for users — a repo
that set `python: deep` today automatically gets the richer engine when it
arrives. The strategy is declared once; the engine grows into it.

### What `off` actually does

`off` is the one depth that changes behavior today, and it is deliberately
scoped:

- It drops **source** artifacts of that language (files whose extension maps to
  the language) *before any analyzer runs*, so they contribute no findings from
  the pattern analyzers (secrets, AI, IaC, data, slop, variants, …).
- It does **not** touch non-source artifacts. Lockfiles, configuration files,
  container definitions, and AI-component files are never gated by the language
  profile — turning off a language must not silently disable dependency-CVE,
  IaC, or secret scanning of unrelated files. In particular, dependency scanning
  still reads `package-lock.json` even with `javascript: off`.
- The filter is applied on the discovered artifact set with input order
  preserved, so scans stay **deterministic**.

## Auditability

The resolved per-language depth for a scan is recorded in the JSON report meta
under `sast_languages`, so a reviewer can see exactly which languages were
scanned at which depth without re-deriving defaults from config:

```json
{
  "meta": {
    "schema_version": "1.0.0",
    "tool_name": "nox",
    "sast_languages": {
      "python": "deep",
      "go": "standard",
      "rust": "off"
    }
  }
}
```

The field is omitted when no profile applies (for example, git-history scans).
