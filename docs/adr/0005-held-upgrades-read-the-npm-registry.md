# ADR 0005: A held npm upgrade names its parent release from the npm registry

- Status: Accepted
- Date: 2026-11-14
- Deciders: nox maintainers
- Supersedes: —

## Context

A fix for an npm package the project does not list, which a parent's range
keeps below the fixed version, cannot be applied: `nox fix apply` refuses it
as held. The plan said "upgrade express@4.21.2 to a release that depends on a
fixed qs". That is true, and it leaves the reader to search express's release
history. On the first-run walkthrough app, express 4.21.2 held body-parser,
path-to-regexp and qs (eight advisories), and the answer is 4.22.3. Nothing in
the lockfile says so: express 4.22.1 already allows qs 6.16, but body-parser
stays at 1.20.3 under it and keeps its own pin on qs 6.13.0.

Answering takes each release's declared dependency ranges, which only the
registry has. nox already reads the npm registry directly for
`nox fix --outdated`. Maven parent POMs go through NOX Intelligence, which
fetches them from Maven Central.

## Decision

`nox fix plan` (and the MCP `fix_plan` tool, when its scan was online) reads
the abbreviated release document (`application/vnd.npm.install-v1+json`, the
one `npm install` reads) of each package it needs from `registry.npmjs.org`,
only for held npm upgrades. `--offline` reads none, and the plan keeps its
generic advice.

`npmtree.ParentRelease` answers the way npm re-resolves. It replaces the
listed parent with each later release in turn. A dependency whose locked copy
still satisfies the new range keeps that copy and its locked tree. One that
does not becomes the highest published release inside the range, with that
release's declared dependencies. The first release under which every copy of
every held package in the parent's tree reaches its fix is named. A release on
the installed major is preferred over a later major. Held items under one
parent are answered together, so one upgrade is named for all of them.

The direct registry, not NOX Intelligence:

- The registry is the package's own source of truth, and this is the same
  host `nox fix --outdated` and `npm install` already talk to. Routing it
  through the service adds a hop and an endpoint for no gain in what is
  learnt.
- What is sent is package names a user's own `npm install` sends, never a
  path or a version of the project.
- The Maven case differs: a parent POM is a file the build needs, and the
  service caches and verifies it for every client.

## Consequences

- The plan names the upgrade, its command and what else it frees; JSON carries
  it in `parent_upgrades`. A `[network]` line on stderr (a note in MCP) names
  every package asked.
- A plan built with a registry depends on what the registry has published when
  it is built. A plan built without one (offline, verify, the LSP) stays a
  function of the findings and the files.
- The simulation does not model npm's hoisting and deduplication. It follows
  each path on its own, and gives a re-resolved dependency the highest release
  in its range. npm may instead reuse a copy already installed elsewhere that
  satisfies the range, and that copy can be below the fix. The plan's advice
  is a prediction; `nox fix verify` after the upgrade is the check. On the
  walkthrough app, real npm 11.20 moved body-parser to 1.20.9, path-to-regexp to
  0.1.13 and qs to 6.16.2 under express 4.22.3, as predicted. Only packages
  that hold the copy (load it with a range that excludes the fix) lead to an
  ancestor. A package that loads the same copy with a range that allows the
  fix is not named: npm moves the copy under it.
- `apply --include-review` makes the parent upgrade, once per parent and
  release, not once per held item, and each held item reads the lockfile back
  afterwards: a copy npm left below the fix fails that item. It needs review,
  not the safe set, because the release is a prediction of npm's
  re-resolution.
- A registry that cannot be read is reported as that, never as "no release
  frees it".
