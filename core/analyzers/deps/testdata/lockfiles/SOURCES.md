# Real lockfile fixtures

Trimmed from real projects, not hand-written. A fixture the author shapes tends
to match the parser the author wrote; these exist to catch the cases nobody
thought of.

Each is the first ~400 lines of an upstream lockfile, preserving header,
structure and the shapes that matter (scoped packages, peer suffixes, protocol
ranges, nested tables).

| File | Source |
|---|---|
| `yarn-v1.lock` | facebook/react @ v18.2.0 — `yarn.lock` |
| `pnpm-v6.yaml` | vuejs/core @ v3.4.21 — `pnpm-lock.yaml` |
| `poetry.lock` | python-poetry/poetry @ main — `poetry.lock` |

pnpm v9 is covered by an inline fixture in `parsers_ecosystem_test.go` rather
than a vendored file: it was the format that yielded zero packages while both
vendored ones parsed fine, which is exactly why breadth of format version
matters more than size of any single file.
