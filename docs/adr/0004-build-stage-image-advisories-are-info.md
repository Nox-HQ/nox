# ADR 0004: An advisory in a build-only Dockerfile stage is recorded at info

- Status: Accepted
- Date: 2026-11-14
- Deciders: nox maintainers
- Supersedes: —

## Context

Since 1.63.0 a scan reads the packages inside every digest-pinned base image a
Dockerfile names, and checks them for known vulnerabilities. It read every
FROM the same way. In a multi-stage build only the final stage is published;
an earlier stage is where the artifact is built, and its image is discarded
unless the final stage is built on it or copies files out of it.

nox's own Dockerfile builds a static Go binary (`CGO_ENABLED=0`) on
`golang:1.27-alpine` and copies that one file onto distroless. On 2026-11-14
ALPINE-CVE-2026-4738 (zlib 1.3.2-r1, fixed in 1.4-r0) was reported against
the builder at medium, gating, with "move the FROM line to a newer digest" —
and no golang image with the fixed zlib existed yet. The shipped image holds no
zlib, and the binary does not link one. nox graded itself B on this finding
alone.

A rating that stands for something that does not ship is the claim nox has
already stopped making elsewhere: a Go advisory for a package the build does
not link has been recorded at info since 1.58.0.

## Decision

`buildOnlyStages` (core/analyzers/deps/stages.go) decides, for each image a
Dockerfile names, whether its stage reaches the final image. A stage ships
when it is the final stage, when a shipped stage is built `FROM` it, or when a
shipped stage copies from it (`COPY --from=<name or index>`) any path that can
hold an installed package's files: `/` or anything under `bin`, `sbin`, `lib*`,
`usr`, `etc`, `var` or `opt`, a relative path (read from the stage's root), a
variable, or a wildcard in the first segment. Every other stage is build-only.

An advisory for a package inside a build-only stage's image is recorded at
info, like an unlinked Go advisory: not dropped, not gating. The finding keeps
its rating in `original_severity`, says `severity_source: build_stage_only`,
names the stage in `image_stage` (and `image_stage_shipped: false`), and its
message says what `--target <stage>` would mean.

Uncertainty resolves toward "ships". A `FROM` or `COPY --from` naming a
variable makes every stage of that Dockerfile count as shipped. A
`COPY --from` an image, not a stage, says nothing about this Dockerfile's
images.

## Consequences

- nox's builder advisory is info; the self-scan grades A. Any Dockerfile that
  builds on a full toolchain image and ships a slim one stops failing on the
  toolchain image's advisories.
- `docker build --target <stage>` publishes a stage the Dockerfile does not
  ship, and the target is named outside the Dockerfile (a CLI flag, compose,
  bake). nox cannot see it. The finding names the stage and says so, and the
  rating is kept in `original_severity`. There is no setting yet to tell nox
  which stages a project publishes: `severity_override` is per rule and
  `conditional_severity` matches rules and paths, so neither separates a
  builder's finding from the shipped image's in one Dockerfile. If a project
  that publishes intermediate stages needs it, the setting to add is a list of
  shipped stage names, read by `buildOnlyStages`.
- A builder compromised through a vulnerable package can still poison the
  artifact. That is a supply-chain risk of the build environment, which an
  advisory's CVSS does not rate, and which pinning the builder by digest (which
  nox already requires before it reads an image) addresses.
- The stage analysis is index-aligned with ParseDockerfile's images and shares
  its skip rule (`skipImageRef`); TestBuildOnlyStages fails if the two walks
  disagree about how many images a Dockerfile names.
