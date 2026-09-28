"""Score nox and Semgrep p/default on the OWASP Benchmark for Java 1.2:
per category TPR - FPR (Youden), a case counts as flagged when a finding in its
file carries the category's CWE."""
import json,re,csv,collections,sys
out=sys.argv[1] if len(sys.argv)>1 else 'nox-out'
exp={}
for row in csv.reader(open('BenchmarkJava/expectedresults-1.2.csv')):
    if row[0].startswith('#'): continue
    exp[row[0]]=(row[1],row[2]=='true',int(row[3]))
HASH=('md5','sha-1','sha1','md4','md2')
def nox_cwe(f):
    m=f.get('Metadata') or {}
    c=int(re.sub(r'\D','',m.get('cwe','0') or '0') or 0)
    if f['RuleID']=='CRYPTO-001':
        return 328 if (m.get('algorithm','').lower() in HASH) else 327
    return {338:330}.get(c,c)
def hits(pairs):
    h=collections.defaultdict(set)
    for f,c in pairs:
        m=re.search(r'(BenchmarkTest\d+)',f)
        if m and c: h[m.group(1)].add(c)
    return h
nox=hits((f['Location']['FilePath'],nox_cwe(f)) for f in json.load(open(f'{out}/findings.json'))['findings'])
sg=[]
for r in json.load(open('semgrep.json'))['results']:
    for c in (r['extra'].get('metadata') or {}).get('cwe') or []:
        m=re.match(r'CWE-(\d+)',c)
        if m: sg.append((r['path'],{338:330,916:328}.get(int(m.group(1)),int(m.group(1)))))
sg=hits(sg)
def score(h):
    per=collections.defaultdict(lambda:[0,0,0,0])
    for t,(cat,vuln,cwe) in exp.items():
        flagged=cwe in h.get(t,set()); k=per[cat]
        if vuln: k[0 if flagged else 1]+=1
        else: k[2 if flagged else 3]+=1
    return per
N,G=score(nox),score(sg)
print(f"{'category':13} {'cases':>5}  {'nox TPR/FPR':>13} {'score':>6}   {'semgrep TPR/FPR':>15} {'score':>6}")
tn=tg=0
for cat in sorted(N,key=lambda c:-sum(N[c])):
    def s(k): tpr=k[0]/max(1,k[0]+k[1]); fpr=k[2]/max(1,k[2]+k[3]); return tpr,fpr,(tpr-fpr)*100
    x=s(N[cat]); y=s(G[cat]); tn+=x[2]; tg+=y[2]
    print(f"{cat:13} {sum(N[cat]):5}  {x[0]*100:5.0f}%/{x[1]*100:4.0f}% {x[2]:6.0f}   {y[0]*100:7.0f}%/{y[1]*100:4.0f}% {y[2]:6.0f}")
print(f"{'AVERAGE':13} {'':5}  {'':13} {tn/len(N):6.1f}   {'':15} {tg/len(N):6.1f}")
