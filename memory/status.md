---
updated: 2026-07-19
---
## Current State

nox is a security scanner (SAST, secrets, IaC, container, AI-component and
dependency analysis) shipping as a signed binary + Docker image, consumed across
the klarlabs/felixgeelhaar fleet through the reusable
`klarlabs-studio/.github/.github/workflows/go-ci.yml`, which pins a specific nox
version + sha256. Latest release **v1.10.0** (2026-07-19). The plugin registry
lives in its own repository (Nox-HQ/registry); core only *consumes* the published
index over HTTP. Release flow is relicta-driven (`.relicta.yaml`, `.relicta/`),
tags `v*` trigger `release.yml` → goreleaser + cosign signing + ghcr image.

## Last Session Summary

v1.10.0 shipped three fixes to Go dependency scanning (#248) that between them
had made it close to non-functional: versions were read from `go.sum` (the whole
module graph, ~99% not in the build), severity was never populated (every finding
`medium` with an empty summary — so a critical dependency CVE could never trip a
high/critical gate), and advisories matched per module rather than per affected
import path. Found by measuring, not from a bug report.

## Next Session Should

Fix the release tooling before the next cut: **`relicta notes` exits 1 silently**
(`.relicta.yaml` has `ai.enabled: true` with `model: gpt-4`; the failure is
swallowed and there is no `--no-ai` flag — it is opt-in `--ai`), and **`relicta
approve` renders `0.0.0` / `0 commits`** on its confirmation screen while the
state file holds the correct version. v1.10.0's changelog had to be hand-written
because of the first, and the second is alarming on a release-gating screen.

## Blocked / Waiting

- Nothing blocking. v1.10.0 is released, signed, and the fleet pin is bumped.
