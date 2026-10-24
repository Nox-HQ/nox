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
| `pnpm-v5.4/pnpm-lock.yaml` | vuejs/core @ v3.2.47 — `pnpm-lock.yaml` (lockfileVersion 5.4) |
| `pnpm-v6-peers/pnpm-lock.yaml` | vuejs/core @ v3.4.21 — `pnpm-lock.yaml` (lockfileVersion 6.0) |
| `pnpm-v9/pnpm-lock.yaml` | vercel/ai @ 6c6c2210b9532a4c369615c044a16d595f3db117 — `pnpm-lock.yaml` (9.0) |
| `pnpm-v9-multidoc/pnpm-lock.yaml` | trpc/trpc @ 1c9bf51ea572fd46fa52fb725999b8d0c6950386 — `pnpm-lock.yaml` (9.0, two YAML documents) |
| `pnpm-v9-git-tarball/pnpm-lock.yaml` | alchemyplatform/modular-account @ ab9c0c24752d83f79ba7b8c112797502d2c2c5a5 — `pnpm-lock.yaml` (9.0) |

The `pnpm-v*` excerpts other than `pnpm-v6` were cut by a script that copies
whole entries verbatim (key line plus every deeper-indented line) and re-parses
the result with PyYAML; no line was edited. Each keeps the header,
`settings:` where present, one importer, and the entries chosen for the shapes
that broke the line-scanning parser:

- `peerDependenciesMeta:` blocks keyed by scoped names, which became phantom
  packages ("@angular" at version "compiler") — all five.
- peer suffixes: v5's `_peer@x+peer2@y` and hashed `_td6yqss6ra3qoebludh4ctrhym`,
  v6's `(peer@x)(peer2@y)`, v9's `snapshots:` keys with nested and
  `patch_hash=` suffixes.
- names containing `_` (`string_decoder`, `evp_bytestokey`,
  `@types/babel__core`), which the old peer-suffix stripper truncated.
- the same package twice with different peer suffixes (`vite/4.0.4`, v5.4).
- `importers:` dependency maps, keyed by scoped names.
- the two-document lockfile pnpm writes when it manages its own version: the
  whole first document (pnpm itself) is kept.
- git and tarball dependencies keyed by URL, whose version is in a `version:`
  field.

The pnpm inline fixtures in `parsers_ecosystem_test.go` predate these and stay
as minimal cases.
