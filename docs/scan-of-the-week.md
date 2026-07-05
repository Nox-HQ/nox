# Scan of the Week — runbook

The "Scan of the Week" routine scans a notable third-party AI/LLM repository,
writes up the findings as a draft blog post on
[nox-hq.dev](https://github.com/nox-hq/nox-hq.dev), and advances the rotation
queue. This runbook is the process of record — the queue itself lives in
[`docs/scan-of-the-week-queue.txt`](./scan-of-the-week-queue.txt).

## The routine

1. Pop the top non-comment line of the queue (`<org>/<repo>[@<ref>]`).
2. Scan it: `nox scan <path> --format json,sarif -o out/`.
3. Triage the findings, write a draft post to
   `nox-hq.dev/src/content/blog/scan-of-the-week-<repo>.md`.
4. Mark the queue line `# DONE <date>: <org>/<repo> — <one-line summary>` and
   commit (queue update + draft post in one PR).

## The egress constraint (why #136 happened)

The scheduled session that runs this routine is **network-restricted**: its git
proxy only permits `nox-hq/nox` and `nox-hq/nox-hq.dev`, so a direct
`git clone https://github.com/<org>/<repo>` of a third-party target fails with a
`403` (see #136). This is deliberate — the scan session should not have broad
outbound access.

The scan itself needs **no** network: nox is offline-first, and Scan of the Week
always runs it with `--offline` (there is nothing to gain from OSV here — the
write-up is about nox's own rule families, not CVE enrichment). So the only step
that needs the network is fetching the source, and that is separable.

## The fix: pre-clone, then scan a local path

Fetch the target in an environment that *is* allowed outbound (a maintainer's
laptop, or a dedicated fetch step with a wider allowlist), hand the scan session
a **local path**, and run nox fully offline. No network-policy change to the
scan session is required.

```bash
# 1. Pre-clone (run where github.com is reachable) — shallow, read-only.
TARGET="modelcontextprotocol/servers"        # top of the queue
git clone --depth 1 "https://github.com/${TARGET}.git" /tmp/sotw-target

# 2. Scan the local path — fully offline, no egress.
nox scan /tmp/sotw-target --offline --format json,sarif -o /tmp/sotw-out

# 3. Summarize + draft the post from /tmp/sotw-out/findings.json, then
#    strike the queue line and open the PR against nox-hq.dev + this repo.
```

If you run the whole routine on a machine with normal GitHub access, steps 1–2
collapse into a single `nox scan` after a plain clone — the pre-clone split only
matters inside the restricted scheduled session.

### Automating the split

For the scheduled job, add a **fetch stage** (a step or job with a github.com
allowlist) that shallow-clones the queue's top target into a shared path (an
artifact or a mounted volume), then let the restricted scan stage read that path
offline. This is option 2 from #136 and needs no change to the scan session's
egress policy.

## Notes

- Always `--offline`. The post is about nox's deterministic rule coverage; OSV
  enrichment adds noise and a network dependency for no benefit here.
- Expect high raw counts dominated by non-source noise (notebook image data,
  lockfile hashes, minified/SVG blobs). Triage to the handful of real findings —
  the past entries in the queue header show the pattern (often 0–1 true
  positives out of hundreds of thousands).
- If a scan surfaces a false-positive rule pattern, fix the rule in this repo as
  part of the same cycle (that is how several FP fixes shipped historically).
