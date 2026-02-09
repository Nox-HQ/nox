# nox-registry

Official Nox plugin registry index, deployed to Cloudflare Pages.

## Architecture

```
registry.nox-hq.dev/index.json  ← static file served by Cloudflare Pages
```

## How it works

1. Plugin author pushes a semver tag to their plugin repo
2. GitHub Actions builds, signs, and creates a release
3. Release workflow dispatches to this repo with a version fragment
4. This repo merges the fragment into `index.json`
5. Cloudflare Pages deploys the updated index

## Files

- `index.json` — The registry index (schema v2)
- `schema.json` — JSON Schema for validation
- `merge-version.sh` — Script to merge version fragments
- `deploy.yml` — GitHub Actions workflow for validation and deployment

## Cost

$0 — Cloudflare Pages free tier + GitHub Actions free for public repos.
