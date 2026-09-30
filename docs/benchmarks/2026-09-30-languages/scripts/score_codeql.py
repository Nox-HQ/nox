"""Score nox and Semgrep on CodeQL query-test fixtures (vendor-authored; bias
risk). Truth: lines marked `$ Alert` or `$ MISSING: Alert` (not `SPURIOUS`)
are vulnerable sink lines. Per CWE directory: recall = alert lines with a
finding of that CWE within one line; precision = findings of that CWE in the
directory that land on an alert line.
usage: score_codeql.py ROOT nox-findings.json [semgrep.json] [ext,ext]"""
import json,os,re,sys,collections
root=sys.argv[1]; noxf=sys.argv[2]
sgf=sys.argv[3] if len(sys.argv)>3 and sys.argv[3]!='-' else None
exts=tuple(sys.argv[4].split(',')) if len(sys.argv)>4 else ('.js','.ts','.jsx','.tsx','.mjs','.cjs')
EQ={23:22,36:22,73:22,80:79,81:79,83:79,77:78,95:94,338:330,916:328,1333:400,99:22}
DIRCWE=lambda d:int(re.search(r'(?i)CWE-0*(\d+)',d).group(1))
ALERT=re.compile(r'\$\s*(?:MISSING:\s*)?Alert\b')
truth=collections.defaultdict(set)
for dp,_,fs in os.walk(root):
    m=re.search(r'(?i)CWE-\d+',dp)
    if not m: continue
    cwe=EQ.get(DIRCWE(m.group(0)),DIRCWE(m.group(0)))
    for f in fs:
        if not f.endswith(exts): continue
        p=os.path.relpath(os.path.join(dp,f),root)
        for i,l in enumerate(open(os.path.join(dp,f),errors='ignore'),1):
            if ALERT.search(l) and 'SPURIOUS' not in l: truth[(p,cwe)].add(i)
def load_nox(fn):
    out=collections.defaultdict(set)
    for f in json.load(open(fn))['findings']:
        c=int(re.sub(r'\D','',(f.get('Metadata') or {}).get('cwe','0') or '0') or 0)
        if f['RuleID']=='CRYPTO-001': c=328 if (f.get('Metadata') or {}).get('algorithm','').lower() in('md5','sha1','sha-1') else 327
        c=EQ.get(c,c)
        if c: out[(f['Location']['FilePath'].lstrip('./'),c)].add(f['Location']['StartLine'])
    return out
def load_sg(fn):
    out=collections.defaultdict(set)
    for r in json.load(open(fn))['results']:
        for cw in (r['extra'].get('metadata') or {}).get('cwe') or []:
            m=re.match(r'CWE-(\d+)',cw)
            if m: c=int(m.group(1)); out[(r['path'].lstrip('./'),EQ.get(c,c))].add(r['start']['line'])
    return out
def score(found):
    per=collections.defaultdict(lambda:[0,0,0,0])  # alerts, hit, findings, onalert
    cwes={c for (_,c) in truth}
    for (p,c),lines in truth.items():
        fl=found.get((p,c),set())
        per[c][0]+=len(lines); per[c][1]+=sum(1 for l in lines if any(abs(l-x)<=1 for x in fl))
    for (p,c),fl in found.items():
        if c not in cwes: continue
        tl=truth.get((p,c),set())
        per[c][2]+=len(fl); per[c][3]+=sum(1 for x in fl if any(abs(l-x)<=1 for l in tl))
    return per
A=score(load_nox(noxf)); B=score(load_sg(sgf)) if sgf else collections.defaultdict(lambda:[0,0,0,0])
print(f"{'CWE':8} {'alerts':>6}  {'nox recall':>10} {'prec':>6} {'n':>5}   {'semgrep recall':>14} {'prec':>6} {'n':>5}")
for c in sorted(A,key=lambda c:-A[c][0]):
    a=A[c]; b=B[c]
    r=lambda k:f"{100*k[1]/max(1,k[0]):5.0f}%"; pr=lambda k:(f"{100*k[3]/k[2]:5.0f}%" if k[2] else "    -")
    print(f"CWE-{c:<4} {a[0]:6}  {r(a):>10} {pr(a):>6} {a[2]:5}   {r(b):>14} {pr(b):>6} {b[2]:5}")
