"""Score nox and Semgrep against a bentoo-sarif truth file (flawgarden format):
each result is kind fail (vulnerable) or pass (safe) with a CWE ruleId and a
file. A case is flagged when any finding in its file carries the case's CWE,
after the scorecard's equivalences. Per-CWE Youden (TPR - FPR), averaged.
usage: score_sarif.py truth.sarif nox-findings.json [semgrep.json] [prefix-to-strip]"""
import json,re,collections,sys
EQ={23:22,36:22,73:22,80:79,81:79,83:79,77:78,95:94,338:330,916:328,91:643}
HASH=('md5','sha-1','sha1','md4','md2')
def norm(c): return EQ.get(c,c)
truth,noxf=sys.argv[1],sys.argv[2]
sgf=sys.argv[3] if len(sys.argv)>3 and sys.argv[3]!='-' else None
strip=sys.argv[4] if len(sys.argv)>4 else ''
import os
ONLY=set(int(x) for x in os.environ.get('CWES','').split(',') if x)
INPUT=os.environ.get('INPUT','')
FILEPAT=os.environ.get('FILE','')
cases={}
for r in json.load(open(truth))['runs'][0]['results']:
    loc=r['locations'][0]['physicalLocation']
    uri=loc['artifactLocation']['uri']; reg=loc.get('region')
    c=norm(int(r['ruleId'].split('-')[1]))
    if ONLY and c not in ONLY: continue
    if INPUT and not re.search(INPUT,(r.get('properties') or {}).get('input','')): continue
    if FILEPAT and not re.search(FILEPAT,uri): continue
    span=(reg['startLine'],reg.get('endLine',reg['startLine'])) if reg else None
    cases[(uri,c,span)]=r['kind']=='fail'
def key(p):
    p=p.replace('\\','/')
    if strip and p.startswith(strip): p=p[len(strip):]
    return p.lstrip('./')
def nox_cwe(f):
    m=f.get('Metadata') or {}
    c=int(re.sub(r'\D','',m.get('cwe','0') or '0') or 0)
    if f['RuleID']=='CRYPTO-001':
        return 328 if (m.get('algorithm','').lower() in HASH) else 327
    return norm(c)
N=collections.defaultdict(set)
for f in json.load(open(noxf))['findings']:
    c=nox_cwe(f)
    if c: N[key(f['Location']['FilePath'])].add((c,f['Location'].get('StartLine',0)))
G=collections.defaultdict(set)
if sgf:
    for r in json.load(open(sgf))['results']:
        for c in (r['extra'].get('metadata') or {}).get('cwe') or []:
            m=re.match(r'CWE-(\d+)',c)
            if m: G[key(r['path'])].add((norm(int(m.group(1))),r['start']['line']))
def score(h):
    per=collections.defaultdict(lambda:[0,0,0,0])
    for (uri,cwe,span),vuln in cases.items():
        fl=any(c==cwe and (span is None or span[0]<=l<=span[1]) for c,l in h.get(uri,()))
        k=per[cwe]
        if vuln: k[0 if fl else 1]+=1
        else: k[2 if fl else 3]+=1
    return per
def s(k): tpr=k[0]/max(1,k[0]+k[1]); fpr=k[2]/max(1,k[2]+k[3]); return tpr,fpr,(tpr-fpr)*100
A,B=score(N),score(G)
print(f"{'CWE':8} {'cases':>6}  {'nox TPR/FPR':>13} {'score':>6}   {'semgrep TPR/FPR':>15} {'score':>6}")
ta=tb=0
for c in sorted(A,key=lambda c:-sum(A[c])):
    x=s(A[c]); y=s(B[c]); ta+=x[2]; tb+=y[2]
    print(f"CWE-{c:<4} {sum(A[c]):6}  {x[0]*100:5.0f}%/{x[1]*100:4.0f}% {x[2]:6.0f}   {y[0]*100:7.0f}%/{y[1]*100:4.0f}% {y[2]:6.0f}")
print(f"{'AVERAGE':8} {'':6}  {'':13} {ta/len(A):6.1f}   {'':15} {tb/len(A):6.1f}")
