#!/usr/bin/env python3
"""Evidence-unit views over raw nox findings. Research tooling, not a metric.

Every model maps raw findings to units, and every unit keeps the raw finding
refs it absorbed, so nothing collapsed loses its provenance. Descriptive only:
no score, no threshold, no verdict. See RESULT.md for why it stays here.

    python3 independence.py <scan-out-dir> <corpus-dir> <dest-prefix>

<scan-out-dir>/<repo>/findings.json must pair with <corpus-dir>/<repo>/, the
tree that was scanned: source lines are read back from it, because a finding
does not carry its matched text.
"""
import hashlib, json, os, re, sys, collections

VERSION_SEG = re.compile(r"^(?:v?\d+(?:\.\d+){1,3}|edge|latest|stable)$")
LOCALES = set("en es fr de it pt pt-BR pt-PT ru ja ko zh zh-Hans zh-Hant zh-CN zh-TW ar hi tr nl pl vi th id cs sv da fi he uk ro hu el fa bn ms nb sk bg hr en-US en-GB es-ES fr-FR de-DE".split())
GEN_MARK = re.compile(r"(Code generated|DO NOT EDIT|@generated|File generated from our OpenAPI spec|auto-?generated|This file is automatically)", re.I)
LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Cargo.lock", "go.sum"}

# Declared, not derived: corpus-design input. Stainless generates both SDKs.
DECLARED_FAMILY = {
    "openai-openai-python": "stainless-sdk",
    "anthropics-anthropic-sdk-python": "stainless-sdk",
}


def site_path(p):
    kept = [s for s in p.replace("\\", "/").split("/") if not (s in LOCALES or VERSION_SEG.match(s))]
    return "/".join(kept) or p


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


class Repo:
    def __init__(self, root):
        self.root, self.cache = root, {}

    def lines(self, rel):
        if rel not in self.cache:
            try:
                with open(os.path.join(self.root, rel), "rb") as fh:
                    self.cache[rel] = fh.read().decode("utf-8", "replace").splitlines()
            except OSError:
                self.cache[rel] = None
        return self.cache[rel]


def material(rel, lines):
    p = "/" + rel.lower()
    base = os.path.basename(rel)
    if "/cassettes/" in p or "/snapshots/" in p or "/__snapshots__/" in p or "/recordings/" in p:
        return "recorded"
    if base in LOCKFILES or (lines and any(GEN_MARK.search(l) for l in lines[:8])):
        return "generated"
    if re.search(r"/(tests?|__tests__|__fixtures__|fixtures|testdata|e2e|[a-z_]*_tests)/", p) or re.search(r"(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+)$", p):
        return "test"
    if p.endswith((".md", ".mdx", ".rst", ".ipynb", ".txt")) or "/docs/" in p or "/doc/" in p:
        return "docs"
    if re.search(r"/(examples?|cookbook|samples?|demo)/", p):
        return "example"
    return "source"


def h(*xs):
    return hashlib.sha1("\x00".join(map(str, xs)).encode()).hexdigest()[:16]


def load(outdir, corpus):
    raw, memo, fmemo = [], {}, {}
    for repo in sorted(os.listdir(outdir)):
        fj = os.path.join(outdir, repo, "findings.json")
        if not os.path.isfile(fj):
            continue
        r = Repo(os.path.join(corpus, repo))
        for f in json.load(open(fj))["findings"]:
            loc = f["Location"]
            rel, s, e = loc["FilePath"], loc["StartLine"], max(loc["EndLine"], loc["StartLine"])
            ls = r.lines(rel)
            ck = (repo, rel, s, e)
            if ck not in memo:
                if ls:
                    if (repo, rel) not in fmemo:
                        fmemo[(repo, rel)] = hashlib.sha1("\n".join(ls).encode()).hexdigest()[:12]
                    memo[ck] = (h(norm(" ".join(ls[s - 1:e]))), h(norm("\n".join(ls[max(0, s - 4):e + 3]))),
                                fmemo[(repo, rel)], norm(" ".join(ls[s - 1:e]))[:200])
                else:
                    memo[ck] = (None, None, None, None)
            text, win, fhash, preview = memo[ck]
            raw.append(dict(n=len(raw), id=f["ID"], rule=f["RuleID"], repo=repo, path=rel, line=s,
                            text=text, preview=preview, win=win, fhash=fhash, mat=material(rel, ls)))
    return raw


# Each model: raw finding -> unit key. Keys always include the rule.
MODELS = {
    "M0_raw":        lambda x: h(x["rule"], x["n"]),
    "M1_exact_line": lambda x: h(x["rule"], x["text"]) if x["text"] else h(x["rule"], x["repo"], x["path"], x["line"]),
    "M1_window":     lambda x: h(x["rule"], x["win"]) if x["win"] else h(x["rule"], x["repo"], x["path"], x["line"]),
    "M2_path_site":  lambda x: h(x["rule"], x["repo"], site_path(x["path"]), x["line"]),
    "M2_file_copy":  lambda x: h(x["rule"], x["fhash"], x["line"]) if x["fhash"] else h(x["rule"], x["repo"], x["path"], x["line"]),
    "M3_repo":       lambda x: h(x["rule"], x["repo"]),
    "M4_family":     lambda x: h(x["rule"], DECLARED_FAMILY.get(x["repo"], x["repo"])),
}


class UF:
    def __init__(s): s.p = {}
    def f(s, a):
        s.p.setdefault(a, a)
        while s.p[a] != a:
            s.p[a] = s.p[s.p[a]]; a = s.p[a]
        return a
    def u(s, a, b): s.p[s.f(a)] = s.f(b)


def union_authored(raw):
    """M2_authored: a finding is the same authored occurrence as another if ANY
    of path-site, file-copy or context-window says so (transitive closure)."""
    uf = UF()
    for i, x in enumerate(raw):
        uf.f(i)
    for name in ("M2_path_site", "M2_file_copy", "M1_window"):
        first = {}
        for i, x in enumerate(raw):
            k = MODELS[name](x)
            if k in first:
                uf.u(i, first[k])
            else:
                first[k] = i
    return [uf.f(i) for i in range(len(raw))]


def units(raw):
    out = {}
    for name, fn in MODELS.items():
        out[name] = [fn(x) for x in raw]
    out["M2_authored"] = [f"{raw[i]['rule']}#{r}" for i, r in enumerate(union_authored(raw))]
    return out


def describe(raw, keys, rule):
    idx = [i for i, x in enumerate(raw) if x["rule"] == rule]
    res = {}
    for name, ks in keys.items():
        groups = collections.defaultdict(list)
        for i in idx:
            groups[ks[i]].append(i)
        # A unit spanning repos is credited fractionally to each, so the
        # per-repo shares still sum to the unit count.
        per_repo = collections.Counter()
        mats = collections.Counter()
        for g in groups.values():
            rs = sorted({raw[i]["repo"] for i in g})
            for r in rs:
                per_repo[r] += 1 / len(rs)
            ms = collections.Counter(raw[i]["mat"] for i in g)
            mats[ms.most_common(1)[0][0]] += 1
        n = len(groups)
        shares = [v / n for v in per_repo.values()] if n else []
        res[name] = dict(units=n,
                         top_repo=max(per_repo, key=per_repo.get) if n else None,
                         top_share=round(max(shares), 3) if shares else None,
                         eff_repos=round(1 / sum(s * s for s in shares), 2) if shares else None,
                         material=dict(mats))
    return res


def provenance(raw, keys, rule, model):
    groups = collections.defaultdict(list)
    for i, x in enumerate(raw):
        if x["rule"] == rule:
            groups[keys[model][i]].append(i)
    return [dict(unit=k, size=len(g), repos=sorted({raw[i]["repo"] for i in g}),
                 material=sorted({raw[i]["mat"] for i in g}),
                 findings=[f"{raw[i]['repo']}:{raw[i]['path']}:{raw[i]['line']}:{raw[i]['id']}" for i in g])
            for k, g in sorted(groups.items(), key=lambda kv: -len(kv[1]))]


if __name__ == "__main__":
    outdir, corpus, dest = sys.argv[1:4]
    raw = load(outdir, corpus)
    keys = units(raw)
    rules = sorted({x["rule"] for x in raw})
    table = {r: describe(raw, keys, r) for r in rules}
    prov = {r: {m: provenance(raw, keys, r, m) for m in ("M1_window", "M2_path_site", "M2_authored")} for r in rules}
    unread = sum(1 for x in raw if x["text"] is None)
    json.dump(dict(raw_count=len(raw), unreadable=unread, table=table), open(dest + ".table.json", "w"), indent=1)
    json.dump(prov, open(dest + ".provenance.json", "w"))
    json.dump(raw, open(dest + ".raw.json", "w"))
    print(f"{len(raw)} raw findings, {len(rules)} rules, {unread} with unreadable source")
