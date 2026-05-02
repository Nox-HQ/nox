# Plugin Marketplace

Nox plugins live as independent binaries published to GitHub Releases.
The marketplace is a single JSON index file that nox consumes — no
SaaS, no auth, no registry server. Operators add the index URL once;
the index is just a static file in a git repo.

## Default registry

The first nox CLI invocation auto-adds the official registry source:

```
name: official
url:  https://raw.githubusercontent.com/nox-hq/nox/main/registry-scaffold/index.json
```

Operators don't need to run `nox registry add` for the official set.
List or remove with `nox registry list` / `nox registry remove official`.

## How an operator installs a plugin

### Project-level manifest (recommended)

Declare required plugins in `.nox.yaml` the same way you'd list deps
in `package.json` or `Gemfile`. Anyone cloning the project gets the
right plugins automatically; first `nox scan` resolves+installs the
list.

```yaml
# .nox.yaml
plugins:
  required:
    - nox/reachability@>=0.5
    - nox/ai-eval
    - nox/taint-analysis
  registries:
    # Project-level registry overrides; merged with the official
    # source. Use `name=url` to set an explicit name.
    - acme=https://registry.acme.internal/nox/index.json
  # Optional: opt out of scan-time auto-install. Default true.
  # auto_install: false
```

Manual install / refresh:

```bash
nox install         # reads .nox.yaml, resolves+installs all required plugins
```

Auto-install on scan: every `nox scan` checks the manifest and
installs missing entries silently. Operators bypass with
`nox scan --no-auto-install` or by setting `auto_install: false`.

### One-shot CLI (no manifest)

```bash
nox plugin search ai
nox plugin info nox/ai-eval
nox plugin install nox/ai-eval
nox plugin call ai-eval ai_eval endpoint=http://localhost:8080/chat
```

## How a plugin author publishes

Every plugin is its own GitHub repo. The recommended layout:

```
nox-plugin-<name>/
  plugin.yaml        # name, version, track, tools
  main.go            # plugin entrypoint (uses sdk)
  Makefile           # build target produces the platform binary
  .github/workflows/ # release workflow → GitHub Releases
```

### Per-plugin release workflow

A typical release pipeline:

1. Tag the plugin repo: `git tag v0.2.0 && git push --tags`.
2. CI builds binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
   `darwin/arm64`, and `windows/amd64`. Use GoReleaser or a hand-rolled
   matrix; either works as long as artifacts land at predictable URLs.
3. CI publishes a GitHub Release tagged `v0.2.0` with each binary
   archived as `nox-plugin-<name>_<version>_<os>_<arch>.tar.gz` (Windows:
   `.zip`).
4. CI generates a registry index entry and opens a PR against the
   official registry repo (or the operator's private registry).

### Generating the index entry

The `nox plugin entry` subcommand produces a valid JSON entry from
`plugin.yaml` plus the version + repo slug:

```bash
cd path/to/nox-plugin-foo
nox plugin entry --version 0.2.0 --output entry.json
```

The output is a single `PluginEntry` ready to splice into
`registry-scaffold/index.json`'s `plugins` array. Open a PR against
the registry repo with the new entry.

After publishing the binaries you must update `digest` and `size` in
the entry to match the SHA-256 digests of the released archives —
the entry generator stamps `sha256:tbd` placeholders that nox refuses
to install.

### Private registries

For internal-only plugins, operators host their own `index.json` and
register it as an additional source:

```bash
nox registry add https://registry.acme.internal/nox/index.json --name acme
```

Multiple registries are merged; the first match wins. Conflicts are
operator-resolvable with `nox registry remove`.

## Bundled plugins

The default nox release archive includes one plugin pre-bundled:

- `nox-plugin-reachability` — multi-language reachability annotation.
  Auto-registered on first run via `bootstrapBundledPlugins`. Operators
  who want it disabled run `nox plugin remove reachability`.

Bundled plugins coexist with registry-installed ones. The bundled
binary lives next to the main `nox` binary; registry-installed ones
live in `~/.nox/plugins/`.

## Trust model

Every registry entry includes:

- `digest` (SHA-256) — required for install. nox verifies before exec.
- `signature` + `signer_key_pem` — optional Cosign-style signature.
  Future enhancement: enforce signed installs via
  `--require-signature` flag.

Until signature enforcement ships, operators should pin to specific
versions and verify digests out-of-band when the threat model
warrants it.

## Stages of marketplace maturity

| Stage | What works |
|---|---|
| 1. Index-as-JSON (today) | Add registry, search, info, install via direct download |
| 2. Signed installs (next) | Cosign keyless verification on every install |
| 3. Auto-update channel | `nox plugin update --all` polls the index for new versions |
| 4. Dependency graph | Plugins declare deps on other plugins; resolver |
| 5. Private hosting recipes | Documented S3 / Artifactory / Cloud Storage hosting |

Stages 2-5 are tracked individually; the index format is forward-
compatible with all of them (signature + dependency fields exist
already, just not enforced).
