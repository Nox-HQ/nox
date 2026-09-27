"""Dependency advisories: nox vs osv-scanner vs trivy.

Identity of an advisory is the union of every alias any tool reported for it
(GHSA / CVE / GO / PYSEC ...), so GO-2026-1 from one tool and CVE-2026-2 from
another are the same finding when any tool links them.
Unit of comparison: (repo, package, version, advisory). The manifest path is
deliberately not in the key: tools disagree on which file "owns" a package
(go.mod vs go.sum, pyproject vs uv.lock), which is a presentation difference.
"""
import json, os, re, collections, sys

H = os.environ.get("WORK", os.getcwd())
recs = [r for r in json.load(open(os.path.join(H, "records.json"))) if r["cat"] == "dep"]

parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[max(ra, rb)] = min(ra, rb)

for r in recs:
    ids = [i.strip() for i in r["ids"] if i and i.strip()]
    for i in ids[1:]:
        union(ids[0], i)

def npkg(p):
    return re.sub(r"[-_.]+", "-", (p or "").lower())  # PEP 503 style; harmless elsewhere
def nver(v):
    return (v or "").lstrip("v")

def key(r):
    ids = [i for i in r["ids"] if i]
    return (r["repo"], npkg(r["pkg"]), nver(r["ver"]), find(ids[0]) if ids else None)

sets = collections.defaultdict(set)
sample = collections.defaultdict(dict)
for r in recs:
    k = key(r)
    sets[r["tool"]].add(k)
    sample[r["tool"]].setdefault(k, r)

tools = ["nox", "osv", "trivy"]
print("distinct (repo,pkg,version,advisory):")
for t in tools:
    print(f"  {t:6} {len(sets[t]):6}")
allk = set().union(*sets.values())
print(f"  union  {len(allk):6}")
print("\nregions:")
reg = collections.Counter(tuple(t for t in tools if k in sets[t]) for k in allk)
for k, n in reg.most_common():
    print(f"  {'+'.join(k):18} {n}")

print("\nper repo (nox / osv / trivy / union):")
for repo in sorted({k[0] for k in allk}):
    row = [len({k for k in sets[t] if k[0] == repo}) for t in tools]
    print(f"  {repo:36} {row[0]:5} {row[1]:5} {row[2]:5} {len({k for k in allk if k[0]==repo}):5}")

# What does each tool miss that both others have?
if "--misses" in sys.argv:
    for t in tools:
        others = [o for o in tools if o != t]
        miss = (sets[others[0]] & sets[others[1]]) - sets[t]
        print(f"\n== missed by {t} but found by both others: {len(miss)}")
        c = collections.Counter((sample[others[0]][k]["extra"].get("eco"), sample[others[0]][k]["file"].split("/")[-1]) for k in miss)
        for (eco, f), n in c.most_common(12):
            print(f"   {n:5}  eco={eco} manifest={f}")

json.dump({t: sorted(map(list, sets[t])) for t in tools}, open(os.path.join(H, "dep_sets.json"), "w"))
