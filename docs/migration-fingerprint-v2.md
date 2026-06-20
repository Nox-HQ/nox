# Migrating to V2 fingerprints

As of **v1.3.0**, nox computes **V2 (line-independent) fingerprints** by default.

## What changed

A finding's *fingerprint* is the stable ID used to match it across scans — it
backs baselines (`.nox/baseline.json`), OpenVEX waivers that match by
fingerprint, and GitHub code-scanning de-duplication.

| | V1 (old default) | V2 (new default) |
|---|---|---|
| Inputs | `rule_id + file_path + start_line + content` | `rule_id + normalised_file_path + content` |
| Survives line shifts (imports, gofmt, comments)? | ❌ no | ✅ yes |
| Survives scan-root differences (`nox scan ./web` vs `nox scan .`)? | ❌ no | ✅ yes |

V1 invalidated a baselined finding whenever code moved up or down by a line.
V2 drops the line number, so trivial diffs no longer un-suppress findings.

## Do I need to do anything?

- **No existing baseline / fingerprint-based VEX:** nothing to do. New scans use
  V2 automatically.
- **VEX that waives by rule ID** (e.g. `"vulnerability": "SEC-161"`): nothing to
  do — rule-level waivers are fingerprint-independent.
- **An existing `.nox/baseline.json` (or fingerprint-keyed VEX) created under
  V1:** its entries carry V1 fingerprints and will no longer match V2 findings,
  silently un-suppressing them. Migrate (below).

## Migrating an existing baseline

```sh
nox baseline migrate            # re-fingerprints .nox/baseline.json in place, V1 → V2
```

`baseline migrate` scans your project twice — once at V1, once at V2 — matches
findings by location to build an **exact** old→new fingerprint map, and rewrites
each entry's fingerprint **while preserving its `reason`, `owner`, and
`created_at`**. No entry is dropped or duplicated through ambiguity.

Options:

```
nox baseline migrate [path]
  --baseline <path>   baseline file (default: .nox/baseline.json)
  --from <1|2>        source version (default: 1)
  --to   <1|2>        target version (default: 2)
  --prune             drop entries whose finding no longer exists
                      (default: keep and report them)
```

Entries whose finding can no longer be found in the current scan are reported;
they are kept by default (use `--prune` to drop resolved ones).

## Staying on V1

If you can't migrate yet, pin V1 explicitly — any one of:

```sh
export NOX_FINGERPRINT_VERSION=1
nox scan --fingerprint-version 1 .
```

```go
findings.SetFingerprintVersion(findings.FingerprintV1) // Go API
```

V1 remains fully supported; only the *default* changed.
