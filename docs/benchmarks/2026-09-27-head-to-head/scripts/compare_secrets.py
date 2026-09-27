"""Secrets: nox vs gitleaks vs trufflehog, by (repo, file, line).

Several rules on one line are one site: tools differ in how many detectors
fire per token, and a reviewer reads a line once.
Writes sample_secrets.json: a stratified sample per Venn region for hand labelling.
"""
import json, os, collections, random

H = os.environ.get("WORK", os.getcwd())
CORPUS = os.path.realpath(os.environ["CORPUS"])
recs = [r for r in json.load(open(os.path.join(H, "records.json"))) if r["cat"] == "secret"]
tools = ["nox", "gitleaks", "trufflehog"]

sites = collections.defaultdict(lambda: collections.defaultdict(list))
for r in recs:
    sites[(r["repo"], r["file"], r["line"])][r["tool"]].append(r["rule"])

print("findings / distinct sites:")
for t in tools:
    n = sum(1 for r in recs if r["tool"] == t)
    s = sum(1 for v in sites.values() if t in v)
    print(f"  {t:10} {n:6} findings  {s:6} sites")

reg = collections.defaultdict(list)
for k, v in sites.items():
    reg[tuple(t for t in tools if t in v)].append(k)
print("\nsite regions:")
for k in sorted(reg, key=lambda k: -len(reg[k])):
    print(f"  {'+'.join(k):28} {len(reg[k])}")

print("\nper repo sites (nox / gitleaks / trufflehog):")
for repo in sorted({k[0] for k in sites}):
    print(f"  {repo:36}", *(f"{sum(1 for k, v in sites.items() if k[0]==repo and t in v):5}" for t in tools))

def line_of(repo, f, n):
    try:
        with open(os.path.join(CORPUS, repo, f), errors="replace") as fh:
            for i, ln in enumerate(fh, 1):
                if i == n:
                    return ln.rstrip("\n")[:300]
    except OSError:
        return None
    return None

random.seed(20260927)
PER = int(os.environ.get("PER", "40"))
out = []
for k, keys in reg.items():
    pick = keys if len(keys) <= PER else random.sample(keys, PER)
    for s in pick:
        out.append(dict(region="+".join(k), region_size=len(keys), repo=s[0], file=s[1], line=s[2],
                        rules={t: sites[s][t] for t in sites[s]}, text=line_of(*s)))
json.dump(out, open(os.path.join(H, "sample_secrets.json"), "w"), indent=1)
print(f"\nsample: {len(out)} sites -> sample_secrets.json")
