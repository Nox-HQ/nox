# Real lockfile fixtures

Trimmed from real projects, not hand-written. A fixture the author shapes tends
to match the parser the author wrote; these exist to catch the cases nobody
thought of.

Each is a slice of an upstream lockfile, preserving header, structure and the
shapes that matter (scoped packages, peer suffixes, protocol ranges, nested
tables).

They keep their REAL filenames, in per-version directories. That is not
cosmetic: nox skips lockfiles in the secrets analyzer by filename, because
content-addressed integrity hashes match both the entropy rules and the
provider-key regexes. Renaming a fixture to `pnpm-v6.yaml` defeats that skip and
makes nox flag its own test data as leaked credentials — which is exactly what
happened, and is a faithful reproduction of what a user would see if the skip
ever regressed.

| File | Source |
|---|---|
| `yarn-v1/yarn.lock` | facebook/react @ v18.2.0 — `yarn.lock` |
| `pnpm-v6/pnpm-lock.yaml` | vuejs/core @ v3.4.21 — `pnpm-lock.yaml` |
| `poetry/poetry.lock` | python-poetry/poetry @ main — `poetry.lock` |

pnpm v9 is covered by an inline fixture in `parsers_ecosystem_test.go` rather
than a vendored file: it was the format that yielded zero packages while both
vendored ones parsed fine, which is exactly why breadth of format version
matters more than size of any single file.
