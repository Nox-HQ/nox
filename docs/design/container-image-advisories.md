# Checking container base images, inside nox

Issue #1013: a scan inventories `FROM golang:1.26-alpine@sha256:…` and
`FROM node:22-alpine@sha256:…`, then reports, correctly, that the advisory
pipeline has no OSV ecosystem for `docker`, so the images were not checked. The
SBOM lists them; nothing says whether they carry known vulnerabilities.

This note records how nox would check them itself. Handing the job to another
scanner (syft, trivy, grype) and ingesting its output is ruled out: it moves the
capability, and the correctness of the answer, outside nox.

## What an image reference does and does not tell us

`docker` is not an advisory ecosystem because an image is not a package. Its
vulnerabilities belong to what is inside it: the distribution's packages (apk,
dpkg, rpm) and the runtimes and binaries layered on top. OSV covers most of
those under their own ecosystems: `Alpine`, `Debian`, `Ubuntu`, `Rocky Linux`,
`AlmaLinux`, `Red Hat`, `Go` (including the toolchain's `stdlib`), and the
language ecosystems nox already reads.

The reference alone gives none of them. A tag such as `golang:1.26-alpine` names
a Go minor and an Alpine branch, not a patch release or a package set, and it
moves. Only the digest identifies content.

## Design

**Scope: digest-pinned references.** `FROM name@sha256:<digest>` identifies
immutable content, so the answer is reproducible: the same digest always yields
the same package set. A tag-only reference is reported as a degradation ("not
checked: the reference is a tag, which names no fixed content; pin it by
digest"), not resolved. Resolving a tag at scan time would make the scan's
answer depend on when it ran.

**Read the image, do not run it.** For each pinned reference nox:

1. fetches the manifest by digest over the OCI distribution API (an index is
   resolved to the `linux/amd64` manifest, or the platform the Dockerfile
   names), using an anonymous pull token where the registry issues one
   (Docker Hub, ghcr.io, quay.io); a registry that needs credentials is a
   degradation that names it;
2. streams each layer blob, verifies it against its digest, and reads only the
   files that list installed software, applying whiteouts so a file deleted in
   a later layer is gone:
   - Alpine: `lib/apk/db/installed`;
   - Debian and Ubuntu: `var/lib/dpkg/status` and `var/lib/dpkg/status.d/*`
     (distroless);
   - RPM distributions: the rpmdb (`var/lib/rpm/rpmdb.sqlite`), read as
     SQLite without executing anything;
   - the distribution itself: `etc/os-release`, which decides the OSV
     ecosystem and release (for example `Alpine:v3.22`);
   - the Go toolchain: `usr/local/go/VERSION` gives `stdlib` at an exact
     version; Go binaries are read for build info, the same as `go version -m`;
   - language packages already parsed by nox from the filesystem (for example
     `node_modules/*/package.json` and Python `*.dist-info/METADATA`);
3. adds what it found to the inventory as packages of the image, located at the
   `FROM` line, with the image digest and the layer and path they came from;
4. sends them through the existing advisory pipeline. Findings, applicability
   and VEX then work as for any other dependency. A distribution package has no
   import graph, so it stays undetermined unless something else decides it.

**Constraints, held as for the rest of nox.**

- Deterministic: content is addressed by digest, layers are verified, and
  output is sorted. Nothing depends on the tag's current target.
- Read-only: no image is run and no file in it is executed; tar entries are
  read with size limits and path-traversal checks.
- Offline-first: blobs are cached by digest under `~/.nox/cache/oci/`. An
  offline scan uses the cache, and otherwise reports each image as not checked,
  naming why. Fetching is part of online dependency checking, with
  its own switch to turn it off (proposed: `scan.images: false`).
- Bounded: a per-image byte budget, and only the listed paths are kept in
  memory, so a multi-gigabyte image costs its layer download, not its size in
  RAM.

## Order of work

1. Manifest and layer reader with whiteouts, digest verification, budget and
   cache; fixtures are small images built in the test, not pulled.
2. `os-release`, apk and dpkg readers: Alpine and Debian/Ubuntu cover the
   official language images (`golang`, `node`, `python`, each `-alpine` and
   Debian based) and distroless.
3. Go toolchain `VERSION` and build info, which turns `golang:*` into exact
   `stdlib` findings. The build-info half exists: a Go executable anywhere in
   a scanned tree is read from its embedded build info
   (`core/analyzers/deps/gobinary.go`), which is also how nox writes its own
   release SBOMs. What remains is applying it to files read out of image
   layers.
4. RPM, then language packages inside images.
5. Measure on pinned real Dockerfiles: findings per image, precision against
   each distribution's own security tracker, scan-time cost with a cold and a
   warm cache. Only after that is it on by default.

Until then the degradation stays. It is the honest answer: the image is listed
and was not checked.

## Status (2026-11-06)

Steps 1 to 3 are built, behind `scan.images.enabled` (`core/image`,
`core/analyzers/deps/image.go`): the reader, os-release, apk, dpkg and
distroless status.d, and the toolchain `VERSION`. Go executables inside image
layers are not read yet. nox-core gained the `Alpine:` and `Debian:`
ecosystems with apk-tools and dpkg version order (the semver order picked
fixes wrong and read a `~` backport as fixed).

First measurement, three pinned images, read with a cold cache in 7 to 9
seconds each:

| Image | Packages | Advisories |
|---|---|---|
| `golang:1.26-alpine` | 10 apk + Go 1.26 | 0 (OSV queried directly agrees: 0 for all 10) |
| `node:22-bookworm-slim` | 63 dpkg | 98, none with a fix |
| `gcr.io/distroless/static-debian12` | 5 dpkg | (not measured for advisories) |

The 98 are matched correctly (each record is `introduced: 0`, no fix), but
Debian rates many of them `unimportant` in `ecosystem_specific.urgency`, and
nox reports them at the CVSS severity. Carrying Debian's urgency, so a
no-fix, unimportant entry does not read as high or critical, is the next
precision step, and is why this stays off by default.

Debian's urgency now travels with each finding (`distro_urgency`, nox-core
0.15.0), and an entry Debian rates `unimportant` is recorded at info rather
than its CVSS severity. On the same image: 36 of the 98 are `unimportant`
(now info), 61 `not yet assigned` (Debian has not triaged them; they keep
their CVSS severity), 1 `low`. 62 findings gate where 98 did. The advisory
cache key carries a record-schema version, so entries cached before the
field existed are fetched again rather than served without it.

Go executables inside image layers are read too: the build-info record is
found by its magic while the layer streams, and Go 1.18+ store the version
and module list inline after it, so nothing is written to disk. nox's own
1.60.1 image reads as stdlib 1.27.3 and nox-core v0.14.0.

Ubuntu (by the stream os-release names) and AlmaLinux and Rocky Linux
(EL9's sqlite rpmdb, read without a SQLite library, in rpm's version order)
are read too. Checked against the systems' own tools: the rpm read equals
`rpm -qa` in almalinux:9 (158) and rockylinux:9 (141); compareRPM agrees with
rpm 4.16's rpm.vercmp on 3000 generated pairs; for ubuntu:24.04 (66),
almalinux:9 (158) and rockylinux:9 (141) the advisory set equals OSV's for
every package in both directions.

Not read, and reported as such: Red Hat and UBI (per-repository advisories),
rpm's Berkeley DB (EL8 and earlier), SUSE.

### Measurement, 2026-11-09: sixteen pinned images

Sixteen widely used images, pinned by digest, read by nox with OSV asked
directly; then OSV queried for every package nox inventoried. "Missed" counts
advisories OSV lists that nox does not report, after resolving aliases (nox
reports one ID per advisory; OSV lists GO-2025-3553 and GHSA-mh63-6h87-95cp
separately for the same issue). Times are a full `nox scan` on a Dockerfile
holding only the FROM line: cold with an empty image cache, warm from it.

| Image | Components | Advisories | Info (distro-rated) | Missed vs OSV | Extra vs OSV | Cold | Warm |
|---|---|---|---|---|---|---|---|
| `python:3.13-slim` | 61 | 86 | 25 | 0 | 0 | 4.8 s | 1.1 s |
| `python:3.13-alpine` | 20 | 1 | 0 | 0 | 0 | 2.7 s | 0.6 s |
| `node:22-alpine` | 11 | 1 | 0 | 0 | 0 | 4.8 s | 1.0 s |
| `nginx:1.27` | 116 | 467 | 86 | 0 | 0 | 15.6 s | 1.4 s |
| `nginx:1.27-alpine` | 58 | 129 | 0 | 0 | 0 | 7.0 s | 0.8 s |
| `redis:7` | 64 | 99 | 37 | 0 | 0 | 4.4 s | 1.1 s |
| `postgres:17` | 99 | 193 | 48 | 0 | 0 | 14.5 s | 2.5 s |
| `postgres:17-alpine` | 39 | 62 | 0 | 0 | 0 | 7.6 s | 2.2 s |
| `ubuntu:22.04` | 70 | 60 | 4 | 0 | 0 | 5.1 s | 0.9 s |
| `debian:12-slim` | 63 | 98 | 36 | 0 | 0 | 3.1 s | 1.0 s |
| `eclipse-temurin:21-jre` | 101 | 91 | 0 | 0 | 0 | 8.2 s | 1.8 s |
| `golang:1.26` | 120 | 628 | 196 | 0 | 0 | 33.0 s | 6.1 s |
| `traefik:v3.2` | 331 | 207 | 0 | 0 | 0 | 9.8 s | 3.1 s |
| `almalinux:9-minimal` | 101 | 4 | 0 | 0 | 0 | 3.1 s | 0.9 s |
| `rockylinux:9-minimal` | 118 | 81 | 0 | 0 | 0 | 4.0 s | 1.1 s |
| `httpd:2.4` | 82 | 167 | 49 | 0 | 0 | 4.4 s | 1.2 s |

No image was misread, and none produced a not-checked notice. Before alias
resolution traefik showed 54 "missed" and each postgres image 1; all were the
same advisories under their other IDs.

What this does not settle, and is a product decision rather than a
correctness one: an image's advisories are numerous (golang:1.26 628,
nginx:1.27 467), most have no fix in the image's own release, and the first
scan of a large image downloads its layers (golang:1.26 is the slowest at
33 s cold). Turning image reading on by default changes what every online
scan of a Dockerfile reports and fetches.

### Decision, 2026-11-09: on by default, gating only what can be fixed

Image reading is on by default. An image advisory with a fix released keeps
its severity and gates; one with no fix yet is recorded at info with
`original_severity`, because nothing can be installed and a gate on it would
be turned off rather than obeyed. A scan that makes no lookups reads images
from the cache only, so the default never adds a download the user turned
lookups off to avoid.

