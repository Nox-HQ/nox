#!/usr/bin/env python3
"""Metamorphic rule-robustness harness for the `nox` security scanner.

Metamorphic relation under test:
    A *semantics-preserving* edit to a source file must not change nox's
    finding set. Any finding that appears or disappears under such an edit is
    a rule bug (a false positive or a false negative).

This is the same technique that found three nox rule bugs by hand (a blank
line before a Dockerfile `COPY` -> false positive; a comment mentioning
`HEALTHCHECK` -> false negative). The harness automates and scales it, and is
wired into CI as a gate: it exits non-zero on any surviving violation.

Pipeline:
    1. For each seed file, scan the original in isolation  -> "before" findings.
    2. Apply each semantics-preserving mutation (a list of atomic edits) and
       scan the mutated file in isolation                  -> "after" findings.
    3. Diff before/after under a line-shift-invariant equivalence.
    4. For every candidate violation, ADVERSARIALLY re-verify by re-running
       nox on a freshly materialised minimal before/after pair (twice, to also
       catch nondeterminism); drop anything that does not reproduce.
    5. Emit a JSON report and minimal repros, and exit non-zero if any survive.

Seeds are the REAL corpus plus a small committed synthetic set:
    - testdata/precision-suite/          (read-only; never written to)
    - scripts/metamorphic/seeds/         (synthetic Dockerfiles + workflows —
                                          the acute Dockerfile/YAML bug class)

Determinism: seed files are sorted, mutation order is fixed, there is no
randomness, and nox is invoked with --offline. Same repo state => same result.

Run:  python3 scripts/metamorphic/harness.py --bin ./nox
See scripts/metamorphic/README.md for the full write-up.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))  # scripts/metamorphic -> repo
DEFAULT_BIN = os.path.join(REPO_ROOT, "nox")
# Seed roots walked by default: the real labeled corpus (read-only) plus the
# committed synthetic Dockerfile/workflow seeds that exercise the acute
# absence-rule bug class the corpus does not contain.
DEFAULT_SEED_ROOTS = [
    os.path.join(REPO_ROOT, "testdata", "precision-suite"),
    os.path.join(HERE, "seeds"),
]
# Files inside a seed root that are not scan targets.
SEED_SKIP = {"README.md", "baseline.json"}

# ---------------------------------------------------------------------------
# nox invocation
# ---------------------------------------------------------------------------


class Nox:
    def __init__(self, binary):
        self.binary = os.path.abspath(binary)
        self.scans = 0
        if not os.path.exists(self.binary):
            sys.exit(f"nox binary not found: {self.binary} (run `make build`)")

    def scan_dir(self, scan_dir):
        """Scan a directory, return list of finding dicts (order as emitted)."""
        with tempfile.TemporaryDirectory() as out:
            # nox exits non-zero when findings exist; that is NOT an error.
            # --offline guarantees zero network for determinism.
            subprocess.run(
                [self.binary, "scan", scan_dir,
                 "--output", out, "--quiet", "--offline"],
                capture_output=True, text=True,
            )
            self.scans += 1
            fj = os.path.join(out, "findings.json")
            if not os.path.exists(fj):
                return []
            with open(fj) as f:
                data = json.load(f)
        return data.get("findings", [])

    def scan_one_file(self, filename, content_bytes):
        """Materialise a single file (by basename) in a temp dir and scan it.

        Keeping one file per scan dir isolates line-shift semantics to that
        file and makes minimal repros trivial to reproduce.
        """
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, filename)
            with open(path, "wb") as f:
                f.write(content_bytes)
            return self.scan_dir(d)


# ---------------------------------------------------------------------------
# Equivalence / matching  (the heart of the harness)
# ---------------------------------------------------------------------------
#
# A blank-line insert legitimately shifts absolute line numbers, so we must
# NOT treat a pure line shift as a violation. We match findings across an edit
# with a two-layer key:
#
#   Layer 1 (primary): nox's own fingerprint. Fingerprint v2 is documented as
#       line-independent + path-normalised, and we verified it is stable under
#       every mutation class we apply (line shift, whitespace reflow, CRLF,
#       inert comment insertion). So identical fingerprint == same finding,
#       regardless of line number.
#
#   Layer 2 (fallback): (RuleID, normalised-anchor). The anchor is the
#       whitespace-normalised text of the source line the finding points at,
#       taken from the file that was actually scanned. Because the anchor text
#       travels with the line, it is invariant under line shifts. This layer
#       absorbs *benign* fingerprint drift (e.g. a fingerprint that folds in
#       whitespace) so we do not double-report one moved finding as both a
#       false positive and a false negative.
#
# Whatever stays unmatched after both layers is a real delta:
#   before-only  -> a finding DISAPPEARED  (candidate false negative)
#   after-only   -> a finding APPEARED     (candidate false positive)


def norm_ws(s):
    return re.sub(r"\s+", " ", s.strip())


def anchor_for(finding, file_lines):
    """Line-shift-invariant semantic location for a finding."""
    loc = finding.get("Location", {})
    sl = loc.get("StartLine", 0) or 0
    text = ""
    if 1 <= sl <= len(file_lines):
        text = norm_ws(file_lines[sl - 1])
    if not text:
        # File-level / absence finding (e.g. "missing HEALTHCHECK") — anchor to
        # the file so it is matched by rule regardless of where nox pins it.
        text = "<file-level>"
    return (finding["RuleID"], text)


def index_findings(findings, file_text):
    """Return (by_fp, anchor_multiset) for one finding set.

    file_text is the exact bytes-as-text that was scanned (for anchor lookup).
    """
    lines = file_text.split("\n")
    by_fp = {}
    anchors = {}
    for fi in findings:
        fp = fi.get("Fingerprint")
        if fp:
            by_fp.setdefault(fp, []).append(fi)
        a = anchor_for(fi, lines)
        anchors.setdefault(a, []).append(fi)
    return by_fp, anchors


def diff_findings(before, before_text, after, after_text):
    """Return list of violations: {direction, ruleid, anchor, finding}.

    direction: 'disappeared' (before-only) or 'appeared' (after-only).
    """
    b_fp, b_anch = index_findings(before, before_text)
    a_fp, a_anch = index_findings(after, after_text)

    matched_before = set()   # id() of matched before findings
    matched_after = set()

    # Layer 1: fingerprint identity.
    for fp, blist in b_fp.items():
        alist = a_fp.get(fp, [])
        k = min(len(blist), len(alist))
        for i in range(k):
            matched_before.add(id(blist[i]))
            matched_after.add(id(alist[i]))

    # Layer 2: (RuleID, anchor) fallback for still-unmatched findings.
    for anchor, blist in b_anch.items():
        b_un = [f for f in blist if id(f) not in matched_before]
        a_un = [f for f in a_anch.get(anchor, []) if id(f) not in matched_after]
        k = min(len(b_un), len(a_un))
        for i in range(k):
            matched_before.add(id(b_un[i]))
            matched_after.add(id(a_un[i]))

    violations = []
    b_lines = before_text.split("\n")
    a_lines = after_text.split("\n")
    for fi in before:
        if id(fi) not in matched_before:
            violations.append({
                "direction": "disappeared",
                "ruleid": fi["RuleID"],
                "anchor": anchor_for(fi, b_lines)[1],
                "finding": fi,
            })
    for fi in after:
        if id(fi) not in matched_after:
            violations.append({
                "direction": "appeared",
                "ruleid": fi["RuleID"],
                "anchor": anchor_for(fi, a_lines)[1],
                "finding": fi,
            })
    return violations


# ---------------------------------------------------------------------------
# Mutations  (each returns a list of atomic edits; all must be semantics-
# preserving for the file's language)
# ---------------------------------------------------------------------------
#
# An atomic edit is a dict:
#   {"op": "insert", "pos": i, "text": s}   insert line s before original line i
#   {"op": "replace", "idx": i, "text": s}  replace original line i with s
# Working on a list of ORIGINAL lines (no trailing newline entries), we can
# apply any *subset* of edits deterministically — this is what makes minimal-
# repro reduction (ddmin) possible.

COMMENT_PREFIX = {
    ".py": "#", ".tf": "#", ".yml": "#", ".yaml": "#",
    ".go": "//", ".js": "//", ".ts": "//",
    "Dockerfile": "#",
}

# Rule keywords to smuggle inside comments. These are DIRECTIVE / ENGLISH words
# only — never real secrets, emails, or URLs — so the comment is genuinely
# inert. A finding that reacts to one of these words in a comment is a rule
# that greps for keywords without parsing, i.e. a bug.
KEYWORD_COMMENTS = [
    "HEALTHCHECK", "USER appuser", "LABEL maintainer here", "--chown",
    "--no-cache", "digest pinned", "attested", "verified", "sha256 pinned",
    "eval", "os.system", "subprocess", "password handling below",
    "yaml.load", "pickle", "innerHTML", "exec",
]


def comment_prefix_for(filename):
    if filename == "Dockerfile" or filename.startswith("Dockerfile"):
        return "#"
    _, ext = os.path.splitext(filename)
    return COMMENT_PREFIX.get(ext, "#")


def mut_blank_line_top(lines, filename):
    return [("blank_line_top", [{"op": "insert", "pos": 0, "text": ""}])]


def mut_blank_line_bottom(lines, filename):
    return [("blank_line_bottom", [{"op": "insert", "pos": len(lines), "text": ""}])]


def mut_blank_line_before_each(lines, filename):
    edits = [{"op": "insert", "pos": i, "text": ""} for i in range(len(lines))]
    return [("blank_line_before_each", edits)]


def mut_blank_line_after_each(lines, filename):
    edits = [{"op": "insert", "pos": i + 1, "text": ""} for i in range(len(lines))]
    return [("blank_line_after_each", edits)]


def mut_trailing_whitespace(lines, filename):
    edits = [{"op": "replace", "idx": i, "text": ln + "   \t"}
             for i, ln in enumerate(lines) if ln.strip() != ""]
    return [("trailing_whitespace", edits)]


def mut_crlf(lines, filename):
    # Represented as per-line replace adding a CR; joined with \n later, so each
    # line ends \r\n. Minimisable per line.
    edits = [{"op": "replace", "idx": i, "text": ln + "\r"}
             for i, ln in enumerate(lines)]
    return [("crlf", edits)]


def mut_pad_before_trailing_comment(lines, filename):
    """Horizontal-whitespace reflow that is provably inert: widen the gap in
    front of an existing end-of-line comment. Never touches indentation or
    tokens, so it is safe even in Python/YAML."""
    prefix = comment_prefix_for(filename)
    edits = []
    for i, ln in enumerate(lines):
        # find a ' <prefix>' that is not at column 0 (an inline trailing comment)
        m = re.search(r"\S(\s+)(" + re.escape(prefix) + r")", ln)
        if m and ln.lstrip().startswith(prefix) is False:
            pos = m.start(1)
            new = ln[:pos] + "    " + ln[pos:]
            edits.append({"op": "replace", "idx": i, "text": new})
    if not edits:
        return []
    return [("pad_before_trailing_comment", edits)]


def mut_keyword_comments(lines, filename):
    """Insert inert comments that mention rule keywords, at top and after the
    first line. This is the class that caused the real HEALTHCHECK false
    negative. One variant per keyword so repros are minimal by construction."""
    prefix = comment_prefix_for(filename)
    variants = []
    for kw in KEYWORD_COMMENTS:
        text = f"{prefix} {kw}"
        # insert after line 0 (or at top for empty files)
        pos = 1 if lines else 0
        variants.append((f"comment[{kw}]@1",
                         [{"op": "insert", "pos": pos, "text": text}]))
        variants.append((f"comment[{kw}]@top",
                         [{"op": "insert", "pos": 0, "text": text}]))
    return variants


MUTATIONS = [
    mut_blank_line_top,
    mut_blank_line_bottom,
    mut_blank_line_before_each,
    mut_blank_line_after_each,
    mut_trailing_whitespace,
    mut_crlf,
    mut_pad_before_trailing_comment,
    mut_keyword_comments,
]


def apply_edits(orig_lines, edits):
    """Apply a subset of atomic edits to original lines -> new lines list."""
    replaced = {}
    inserts = {}
    for e in edits:
        if e["op"] == "replace":
            replaced[e["idx"]] = e["text"]
        else:  # insert before pos
            inserts.setdefault(e["pos"], []).append(e["text"])
    out = []
    for i in range(len(orig_lines) + 1):
        for t in inserts.get(i, []):
            out.append(t)
        if i < len(orig_lines):
            out.append(replaced.get(i, orig_lines[i]))
    return out


# ---------------------------------------------------------------------------
# Minimal-repro reduction (ddmin over atomic edits)
# ---------------------------------------------------------------------------

def ddmin(edits, predicate):
    """Return a minimal subset of `edits` still satisfying predicate(subset).

    Classic delta-debugging (Zeller) over the edit list.
    """
    if not predicate(edits):
        return edits  # shouldn't happen; caller checks first
    n = 2
    cur = list(edits)
    while len(cur) >= 2:
        chunk = max(1, len(cur) // n)
        subsets = [cur[i:i + chunk] for i in range(0, len(cur), chunk)]
        reduced = False
        # try complements first (remove a chunk)
        for s in subsets:
            comp = [e for e in cur if e not in s]
            if comp and predicate(comp):
                cur = comp
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(cur):
                break
            n = min(len(cur), n * 2)
    return cur


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def read_seed(path):
    with open(path, "rb") as f:
        raw = f.read()
    # Work in text with LF line model; keep no trailing empty element noise.
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    # A trailing newline yields a final "" element; drop it so line indices map
    # to real lines. Re-added on join.
    trailing_nl = text.endswith("\n")
    if trailing_nl and lines and lines[-1] == "":
        lines = lines[:-1]
    return lines, trailing_nl


def join_lines(lines, trailing_nl):
    s = "\n".join(lines)
    if trailing_nl:
        s += "\n"
    return s


def discover_seeds(seed_roots):
    """Return sorted list of (abs_path, display_name) for every scan target.

    display_name is the path relative to the repo root, so multi-root corpora
    report stable, human-readable identities regardless of basename collisions.
    """
    seeds = []
    for root in seed_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if fn in SEED_SKIP:
                    continue
                abs_path = os.path.join(dirpath, fn)
                if not os.path.isfile(abs_path):
                    continue
                display = os.path.relpath(abs_path, REPO_ROOT)
                seeds.append((abs_path, display))
    seeds.sort(key=lambda t: t[1])
    return seeds


def run(seeds, nox):
    candidates = []
    stats = {"files": 0, "mutations_applied": 0}

    for path, display in seeds:
        filename = os.path.basename(path)
        lines, trailing_nl = read_seed(path)
        orig_text = join_lines(lines, trailing_nl)
        before = nox.scan_one_file(filename, orig_text.encode("utf-8"))
        stats["files"] += 1

        for mut in MUTATIONS:
            for label, edits in mut(lines, filename):
                if not edits:
                    continue
                new_lines = apply_edits(lines, edits)
                after_text = join_lines(new_lines, trailing_nl)
                after = nox.scan_one_file(filename, after_text.encode("utf-8"))
                stats["mutations_applied"] += 1
                viols = diff_findings(before, orig_text, after, after_text)
                for v in viols:
                    candidates.append({
                        "seed": display,
                        "filename": filename,
                        "mutation": label,
                        "direction": v["direction"],
                        "ruleid": v["ruleid"],
                        "anchor": v["anchor"],
                        "message": v["finding"].get("Message", ""),
                        "edits": edits,
                        "_orig_lines": lines,
                        "_trailing_nl": trailing_nl,
                    })
    stats["candidates"] = len(candidates)
    return candidates, stats


def verify_and_minimize(candidates, nox):
    """Adversarial self-verification + minimal-repro reduction.

    For each candidate we (a) re-run nox on the exact before/after pair in
    FRESH dirs, twice, and require the delta to reproduce identically; only
    then (b) ddmin the edit set to the smallest repro, re-verifying at the end.
    """
    survivors = []

    def repro(direction, ruleid, filename, orig_lines, edits, trailing_nl):
        """Does applying `edits` produce the given appear/disappear of ruleid?
        Runs twice for determinism."""
        orig_text = join_lines(orig_lines, trailing_nl)
        new_text = join_lines(apply_edits(orig_lines, edits), trailing_nl)
        deltas = []
        for _ in range(2):
            before = nox.scan_one_file(filename, orig_text.encode("utf-8"))
            after = nox.scan_one_file(filename, new_text.encode("utf-8"))
            v = diff_findings(before, orig_text, after, new_text)
            hit = any(x["direction"] == direction and x["ruleid"] == ruleid
                      for x in v)
            deltas.append(hit)
        return all(deltas)

    for c in candidates:
        ok = repro(c["direction"], c["ruleid"], c["filename"],
                   c["_orig_lines"], c["edits"], c["_trailing_nl"])
        if not ok:
            c["verified"] = False
            continue

        pred = lambda subset, c=c: bool(subset) and repro(
            c["direction"], c["ruleid"], c["filename"],
            c["_orig_lines"], subset, c["_trailing_nl"])
        minimal = ddmin(c["edits"], pred)
        # Final confirmation on the minimal set.
        if not pred(minimal):
            minimal = c["edits"]
        c["verified"] = True
        c["minimal_edits"] = minimal
        survivors.append(c)
    return survivors


def write_repro(results_dir, c, idx):
    d = os.path.join(results_dir, "repros",
                     f"{idx:03d}_{c['ruleid']}_{c['direction']}")
    before_dir = os.path.join(d, "before")
    after_dir = os.path.join(d, "after")
    os.makedirs(before_dir, exist_ok=True)
    os.makedirs(after_dir, exist_ok=True)
    orig_text = join_lines(c["_orig_lines"], c["_trailing_nl"])
    new_text = join_lines(apply_edits(c["_orig_lines"], c["minimal_edits"]),
                          c["_trailing_nl"])
    with open(os.path.join(before_dir, c["filename"]), "w") as f:
        f.write(orig_text)
    with open(os.path.join(after_dir, c["filename"]), "w") as f:
        f.write(new_text)
    with open(os.path.join(d, "REPRO.md"), "w") as f:
        f.write(f"# Repro: {c['ruleid']} {c['direction']}\n\n")
        f.write(f"- seed: `{c['seed']}`\n")
        f.write(f"- mutation class: `{c['mutation']}`\n")
        f.write(f"- direction: **{c['direction']}** "
                f"({'false negative' if c['direction']=='disappeared' else 'false positive'})\n")
        f.write(f"- rule message: {c['message']}\n")
        f.write(f"- minimal edit(s): {len(c['minimal_edits'])} atomic edit(s)\n\n")
        f.write("Reproduce:\n\n```\n")
        f.write(f"nox scan before/ --output /tmp/b   # {c['ruleid']} "
                f"{'present' if c['direction']=='disappeared' else 'absent'}\n")
        f.write(f"nox scan after/  --output /tmp/a   # {c['ruleid']} "
                f"{'absent (BUG)' if c['direction']=='disappeared' else 'present (BUG)'}\n")
        f.write("```\n")
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=DEFAULT_BIN,
                    help="path to the nox binary (default: repo ./nox)")
    ap.add_argument("--seeds", action="append", default=None,
                    help="seed root to walk (repeatable; default: precision "
                         "corpus + committed synthetic seeds)")
    ap.add_argument("--results", default=None,
                    help="directory for the JSON report + repros "
                         "(default: a temp dir)")
    ap.add_argument("--limit", type=int, default=None,
                    help="limit number of seed files (for a quick run)")
    args = ap.parse_args()

    seed_roots = args.seeds if args.seeds else DEFAULT_SEED_ROOTS
    seeds = discover_seeds(seed_roots)
    if not seeds:
        sys.exit(f"no seed files found under: {seed_roots}")
    if args.limit:
        seeds = seeds[:args.limit]

    nox = Nox(args.bin)
    results_dir = args.results or tempfile.mkdtemp(prefix="nox-metamorphic-")
    os.makedirs(results_dir, exist_ok=True)

    t0 = time.time()
    candidates, stats = run(seeds, nox)
    survivors = verify_and_minimize(candidates, nox)
    elapsed = time.time() - t0

    # De-duplicate survivors by (seed, ruleid, direction, mutation-class-root).
    seen = set()
    unique = []
    for c in survivors:
        key = (c["seed"], c["ruleid"], c["direction"],
               c["mutation"].split("[")[0])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    for i, c in enumerate(unique):
        c["repro_dir"] = os.path.relpath(write_repro(results_dir, c, i),
                                         results_dir)

    # The JSON report is a committed/uploaded artifact people diff, so it is kept
    # deterministic: no wall-clock (elapsed is printed to stdout only) and no
    # absolute paths (binary is shown relative to the repo when possible).
    try:
        binary_display = os.path.relpath(nox.binary, REPO_ROOT)
    except ValueError:
        binary_display = os.path.basename(nox.binary)
    report = {
        "nox_binary": binary_display,
        "seed_roots": [os.path.relpath(r, REPO_ROOT) for r in seed_roots
                       if os.path.isdir(r)],
        "seed_file_count": len(seeds),
        "mutations_applied": stats["mutations_applied"],
        "total_nox_scans": nox.scans,
        "candidate_violations": stats["candidates"],
        "verified_violations": len(survivors),
        "unique_verified_violations": len(unique),
        "violations": [
            {k: c[k] for k in ("seed", "filename", "mutation", "direction",
                               "ruleid", "anchor", "message", "repro_dir")}
            | {"minimal_edit_count": len(c["minimal_edits"])}
            for c in unique
        ],
    }
    report_path = os.path.join(results_dir, "invariance_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"seed files:            {report['seed_file_count']}")
    print(f"mutations applied:     {report['mutations_applied']}")
    print(f"total nox scans:       {report['total_nox_scans']}")
    print(f"elapsed:               {round(elapsed, 1)}s")
    print(f"candidate violations:  {report['candidate_violations']}")
    print(f"verified violations:   {report['verified_violations']}")
    print(f"unique verified:       {report['unique_verified_violations']}")
    print(f"report:                {report_path}")
    for c in unique:
        print(f"  - [{c['direction']:11s}] {c['ruleid']:9s} "
              f"seed={c['seed']} via {c['mutation']}  -> {c['repro_dir']}")

    if unique:
        print(f"\nFAIL: {len(unique)} metamorphic invariance violation(s). "
              f"See repros under {results_dir}/repros/.", file=sys.stderr)
        sys.exit(1)
    print("\nOK: no metamorphic invariance violations.")
    sys.exit(0)


if __name__ == "__main__":
    main()
