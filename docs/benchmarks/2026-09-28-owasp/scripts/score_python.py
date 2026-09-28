"""Score nox and Semgrep p/default on the OWASP Benchmark for Python 0.1:
per category TPR - FPR (Youden). A case counts as flagged when a finding in
its file carries the category's CWE. Usage: score_python.py <nox output dir>
(run from the directory holding BenchmarkPython/ and semgrep.json)."""
import json,re,collections,csv,sys
OUT=sys.argv[1] if len(sys.argv)>1 else 'nox-out'
norm={327:328, 95:94, 916:328, 338:330}  # same condition, different CWE number
def n(c): return norm.get(c,c)
exp={}
for row in csv.reader(open('BenchmarkPython/expectedresults-0.1.csv')):
    if row[0].startswith('#'): continue
    exp[row[0]]=(row[1],row[2]=='true',n(int(row[3])))
def hits(pairs):
    h=collections.defaultdict(set)
    for f,c in pairs:
        m=re.search(r'(BenchmarkTest\d+)',f)
        if m and c: h[m.group(1)].add(n(c))
    return h
nox=hits((f['Location']['FilePath'], int(re.sub(r'\D','',(f.get('Metadata') or {}).get('cwe','0') or '0') or 0))
         for f in json.load(open(OUT+'/findings.json'))['findings'])
sg=[]
for r in json.load(open('semgrep.json'))['results']:
    for c in (r['extra'].get('metadata') or {}).get('cwe') or []:
        m=re.match(r'CWE-(\d+)',c)
        if m: sg.append((r['path'],int(m.group(1))))
sg=hits(sg)
def score(h):
    per=collections.defaultdict(lambda:[0,0,0,0])  # tp,fn,fp,tn
    for t,(cat,vuln,cwe) in exp.items():
        flagged=cwe in h.get(t,set())
        k=per[cat]
        if vuln: k[0 if flagged else 1]+=1
        else: k[2 if flagged else 3]+=1
    return per
N,G=score(nox),score(sg)
print(f"{'category':15} {'cases':>5}  {'nox TPR/FPR':>13} {'score':>6}   {'semgrep TPR/FPR':>15} {'score':>6}")
tn=tg=0
for cat in sorted(N, key=lambda c:-sum(N[c])):
    a=N[cat]; b=G[cat]
    def s(k):
        tpr=k[0]/max(1,k[0]+k[1]); fpr=k[2]/max(1,k[2]+k[3]); return tpr,fpr,(tpr-fpr)*100
    x=s(a); y=s(b); tn+=x[2]; tg+=y[2]
    print(f"{cat:15} {sum(a):5}  {x[0]*100:5.0f}%/{x[1]*100:4.0f}% {x[2]:6.0f}   {y[0]*100:7.0f}%/{y[1]*100:4.0f}% {y[2]:6.0f}")
print(f"{'AVERAGE':15} {'':5}  {'':13} {tn/len(N):6.1f}   {'':15} {tg/len(N):6.1f}")
