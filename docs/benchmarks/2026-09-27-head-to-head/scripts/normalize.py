"""Normalize every tool's output into one record shape.

record = {tool, repo, cat, file, line, rule, pkg, ver, ids, extra}
cat: secret | dep | sast | other
"""
import json, os, glob, sys

H = os.environ.get("WORK", os.getcwd())
OUT = os.path.join(H, "out")
CORPUS = os.path.realpath(os.environ["CORPUS"])


def rel(repo, p):
    p = os.path.realpath(p) if os.path.isabs(p) else p
    root = os.path.join(CORPUS, repo) + os.sep
    return p[len(root):] if p.startswith(root) else p


def rec(tool, repo, cat, file, line, rule, **kw):
    r = dict(tool=tool, repo=repo, cat=cat, file=file, line=int(line or 0), rule=rule,
             pkg=None, ver=None, ids=[], extra={})
    r.update(kw)
    return r


def nox(repo):
    p = os.path.join(OUT, "nox", repo, "findings.json")
    for f in json.load(open(p))["findings"]:
        rid, loc, md = f["RuleID"], f["Location"], f.get("Metadata") or {}
        fam = rid.split("-")[0]
        if rid == "VULN-001":
            ids = [md.get("vuln_id")] + [a for a in (md.get("aliases") or "").split(",") if a]
            yield rec("nox", repo, "dep", loc["FilePath"], 0, rid, pkg=md.get("package"),
                      ver=md.get("version"), ids=ids,
                      extra={"eco": md.get("ecosystem"), "applicability": md.get("applicability")})
        else:
            cat = "secret" if fam == "SEC" else "other"
            yield rec("nox", repo, cat, loc["FilePath"], loc["StartLine"], rid,
                      extra={"sev": f["Severity"], "fam": fam, "msg": f["Message"][:160]})


def gitleaks(repo):
    for f in json.load(open(os.path.join(OUT, "gitleaks", repo + ".json"))) or []:
        yield rec("gitleaks", repo, "secret", rel(repo, f["File"]), f["StartLine"], f["RuleID"],
                  extra={"match": f.get("Match", "")[:160]})


def trufflehog(repo):
    p = os.path.join(OUT, "trufflehog", repo + ".jsonl")
    for ln in open(p):
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        f = json.loads(ln)
        fs = f["SourceMetadata"]["Data"]["Filesystem"]
        yield rec("trufflehog", repo, "secret", rel(repo, fs["file"]), fs.get("line", 0), f["DetectorName"],
                  extra={"raw": (f.get("Raw") or "")[:80]})


def osv(repo):
    d = json.load(open(os.path.join(OUT, "osv", repo + ".json")))
    for res in d.get("results") or []:
        src = rel(repo, res["source"]["path"])
        for pk in res["packages"]:
            pkg = pk["package"]
            for v in pk.get("vulnerabilities") or []:
                yield rec("osv", repo, "dep", src, 0, "osv", pkg=pkg["name"], ver=pkg["version"],
                          ids=[v["id"]] + (v.get("aliases") or []), extra={"eco": pkg.get("ecosystem")})


def trivy(repo):
    d = json.load(open(os.path.join(OUT, "trivy", repo + ".json")))
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            yield rec("trivy", repo, "dep", r["Target"], 0, "trivy", pkg=v["PkgName"], ver=v["InstalledVersion"],
                      ids=[v["VulnerabilityID"]] + (v.get("VendorIDs") or []), extra={"eco": r.get("Type")})


def semgrep(repo):
    d = json.load(open(os.path.join(OUT, "semgrep", repo + ".json")))
    for f in d["results"]:
        md = f["extra"].get("metadata") or {}
        yield rec("semgrep", repo, "sast", rel(repo, f["path"]), f["start"]["line"], f["check_id"],
                  extra={"sev": f["extra"].get("severity"), "category": md.get("category"),
                         "msg": f["extra"].get("message", "")[:160]})


TOOLS = dict(nox=nox, gitleaks=gitleaks, trufflehog=trufflehog, osv=osv, trivy=trivy, semgrep=semgrep)


def load(tools=None, repos=None):
    repos = repos or sorted(os.listdir(CORPUS))
    out = []
    for t in tools or TOOLS:
        for r in repos:
            try:
                out.extend(TOOLS[t](r))
            except FileNotFoundError:
                print(f"missing {t}/{r}", file=sys.stderr)
    return out


if __name__ == "__main__":
    recs = load()
    json.dump(recs, open(os.path.join(H, "records.json"), "w"))
    import collections
    c = collections.Counter((r["tool"], r["cat"]) for r in recs)
    for k in sorted(c):
        print(k, c[k])
