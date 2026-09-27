"""Code analysis: nox (TAINT, CRYPTO, IAC, DATA, MCP ...) vs semgrep p/default.

Match: same repo and file, lines within +/-3. Families nox has that semgrep's
default ruleset does not address (AI, SLOP) are reported separately rather than
counted as unique wins, since p/default does not try to find them.
"""
import json, os, collections, random

H = os.environ.get("WORK", os.getcwd())
C = os.path.realpath(os.environ["CORPUS"])
R = json.load(open(os.path.join(H, "records.json")))
sg = [r for r in R if r["tool"] == "semgrep"]
nx = [r for r in R if r["tool"] == "nox" and r["cat"] == "other" and r["extra"]["fam"] not in ("VULN",)]

def near(a, b, d=3):
    return a["repo"] == b["repo"] and a["file"] == b["file"] and abs(a["line"] - b["line"]) <= d

byfile = collections.defaultdict(list)
for r in nx:
    byfile[(r["repo"], r["file"])].append(r)
sg_matched = [s for s in sg if any(near(s, n) for n in byfile[(s["repo"], s["file"])])]
sgf = collections.defaultdict(list)
for s in sg:
    sgf[(s["repo"], s["file"])].append(s)
nx_matched = [n for n in nx if any(near(n, s) for s in sgf[(n["repo"], n["file"])])]

print(f"semgrep findings {len(sg)}; within 3 lines of a nox finding: {len(sg_matched)}")
print(f"nox code findings {len(nx)}; within 3 lines of a semgrep finding: {len(nx_matched)}")
print("\nsemgrep by category:", collections.Counter(s['extra'].get('category') for s in sg).most_common())
print("semgrep top rules:")
for k, n in collections.Counter(s["rule"] for s in sg).most_common(25):
    print(f"  {n:4} {k}")
print("nox families:", collections.Counter(n["extra"]["fam"] for n in nx).most_common())
print("matched pairs by (nox family, semgrep rule tail):")
pairs = collections.Counter()
for s in sg_matched:
    for n in byfile[(s["repo"], s["file"])]:
        if near(s, n):
            pairs[(n["rule"], s["rule"].split(".")[-1])] += 1
for k, n in pairs.most_common(20):
    print(f"  {n:4} {k}")

def line(r):
    try:
        with open(os.path.join(C, r["repo"], r["file"]), errors="replace") as fh:
            for i, l in enumerate(fh, 1):
                if i == r["line"]:
                    return l.strip()[:200]
    except OSError:
        return None

random.seed(20260927)
sample = []
for name, pool in (("semgrep-only", [s for s in sg if s not in sg_matched]),
                   ("nox-only-code", [n for n in nx if n not in nx_matched and n["extra"]["fam"] in ("TAINT", "CRYPTO", "IAC", "DATA", "MCP", "VARIANT", "AGENTFLOW", "AGENT")])):
    pick = pool if len(pool) <= 40 else random.sample(pool, 40)
    for r in pick:
        sample.append(dict(region=name, pool=len(pool), repo=r["repo"], file=r["file"], line=r["line"],
                           rule=r["rule"], msg=r["extra"].get("msg"), text=line(r)))
json.dump(sample, open(os.path.join(H, "sample_sast.json"), "w"), indent=1)
print(f"\nsample: {len(sample)} -> sample_sast.json")
