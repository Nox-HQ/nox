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
   `stdlib` findings.
4. RPM, then language packages inside images.
5. Measure on pinned real Dockerfiles: findings per image, precision against
   each distribution's own security tracker, scan-time cost with a cold and a
   warm cache. Only after that is it on by default.

Until then the degradation stays. It is the honest answer: the image is listed
and was not checked.
