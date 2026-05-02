# Marketplace static site

Static HTML rendered from `registry-scaffold/index.json`. Same
JSON the CLI consumes drives the human-facing site — single source
of truth.

## Build locally

```bash
go run ./cmd/marketplace-build \
    --index registry-scaffold/index.json \
    --output marketplace/dist

# Serve and preview:
cd marketplace/dist && python3 -m http.server 8000
```

## Deploy

`.github/workflows/marketplace.yml` rebuilds the site on every change
to `registry-scaffold/index.json` or `cmd/marketplace-build/**` and
publishes to GitHub Pages. Configure once under repo Settings → Pages
→ Source = "GitHub Actions".

The site URL is `https://nox-hq.github.io/nox/` (or the configured
custom domain).

## Customising

`cmd/marketplace-build/templates/` holds the HTML templates; styling
lives in `cmd/marketplace-build/assets/style.css`. Both are embedded
via `embed.FS` so the binary ships without runtime file dependencies.

## Adding a plugin

A plugin appears on the marketplace by adding an entry to
`registry-scaffold/index.json` — typically via a PR opened by the
plugin's release pipeline. See `docs/marketplace.md` for the full
publish flow.
