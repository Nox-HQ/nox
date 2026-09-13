"""Classify every SEC rule by the evidence it requires before it will fire.

    python3 scripts/secret-rule-inventory.py <rules.json> [bench.json]

<rules.json> must be a dump of the BUILT rule set -- a JSON array of objects
with id/pattern/keywords/description -- NOT rules parsed out of the YAML or Go
source. Extracting rules from source text with regexes gave wrong answers twice
while this was being written: it paired one rule's `id:` with another rule's
`pattern:`, and it counted 3 English-word keywords where the built set has 11.
Dump it from a throwaway test in core/rules that marshals engine.RuleSet().

Writes docs/design/secret-rule-inventory.json. See secret-rule-inventory.md for
what the A/B/C/D classes mean and what this measurement cannot tell you.
"""
import json, re, collections, os, sys

if len(sys.argv) < 2:
    sys.exit(__doc__)
rules=json.load(open(sys.argv[1]))
# The dump is keyed by the JSON tags in dump_rules_test.go; accept the older
# Go-field-name spelling too so a pre-existing dump still classifies.
_alias={"id":"ID","description":"Description","pattern":"Pattern",
        "matcher_type":"MatcherType","keywords":"Keywords","severity":"Severity",
        "confidence":"Confidence","tags":"Tags","metadata":"Metadata"}
for _r in rules:
    for _lo,_up in _alias.items():
        if _lo in _r and _up not in _r: _r[_up]=_r[_lo]
bench=json.load(open(sys.argv[2] if len(sys.argv)>2 else "docs/benchmarks/2026-Q2/bench.json"))
fire=collections.Counter(); repos=collections.Counter()
for p in bench["projects"]:
    for k,v in (p.get("by_rule") or {}).items(): fire[k]+=v; repos[k]+=1
words=set()
if os.path.exists('/usr/share/dict/words'):
    words={w.strip().lower() for w in open('/usr/share/dict/words') if len(w.strip())>2}

def strip_flags(p): return re.sub(r'^\(\?[a-zA-Z]+\)','',p)

def literals(p):
    """Literal runs the pattern REQUIRES, with regex syntax removed first.

    Group syntax is stripped before extraction because `(?-i:` and `(?i:` are
    regex, not content: reading `-i:` as a literal made SEC-286's explanation
    cite a case-folding flag as the thing that identifies an Okta token."""
    q=strip_flags(p)
    q=re.sub(r'\(\?[a-zA-Z:!=<>-]*','(',q)      # (?i: (?-i: (?: (?!  (?<=
    q=re.sub(r'\[[^\]]*\]','\x00',q)           # char classes
    q=re.sub(r'\{\d+(,\d*)?\}','',q)           # quantifiers
    q=re.sub(r'\\[a-zA-Z]','\x00',q)           # \w \s \d ...
    q=q.replace('\\.', '.')
    out=[]
    for m in re.findall(r'[A-Za-z0-9_.:/\-]{2,}', q):
        m=m.strip('.-_:/')
        if len(m)>=2 and not m.isdigit() and not set(m) <= set('.-_:/'):
            out.append(m)
    return out

def token_class(p):
    m=re.search(r'\[([^\]]+)\]\s*\{(\d+)(?:,(\d*))?\}', p)
    return (m.group(1), int(m.group(2))) if m else None

# Does the pattern bind a key NAME to the value with an assignment?
def binds_assignment(p):
    """Does a key NAME bind the value through an assignment?

    `://` is masked first. Without that, the colon in `smtp://` read as an
    assignment operator and a URL pattern was explained as "binds the key name
    `smtp://` to the value", which is not a sentence anyone can act on."""
    q=strip_flags(p).replace('://', '\x01')
    i=q.find('[')
    head = q if i<0 else q[:i]
    return bool(re.search(r'[=:>]', head)) and bool(literals(head))

def is_structural(p):
    """A URL, ARN or other shape whose literal identifies it without a keyword."""
    q=strip_flags(p)
    return '://' in q or 'arn:' in q.lower()

def classify(r):
    p=r["Pattern"]; kws=r.get("Keywords") or []
    rck=r.get("require_context_keywords") or []
    if r["MatcherType"]=="entropy":
        if rck:
            return "B","an entropy rule gated by require_context_keywords: it reports a high-entropy value only where a nearby line names a secret"
        return "D","an entropy rule with NO proximity gate: entropy alone cannot separate a credential from a long identifier"
    lits=literals(p)
    if is_structural(p):
        return "A", f"the pattern requires the structural literal `{lits[0] if lits else p[:20]}` — a URL or ARN form that identifies itself without any keyword gate"
    if binds_assignment(p):
        return "B", f"the pattern binds the key name `{lits[0]}` to the value with an assignment, so the DESTINATION says the value is credential material"
    if lits:
        return "A", f"the pattern requires the literal `{lits[0]}`, which is discriminative on its own and does not depend on the keyword gate"
    tc=token_class(p)
    if tc and rck:
        return "C", f"the pattern is a bare [{tc[0]}]{{{tc[1]}}} token; its discrimination is the word `{rck[0]}` appearing WITHIN 4 lines and 512 characters of the match"
    if tc and kws:
        return "D", f"the pattern is a bare [{tc[0]}]{{{tc[1]}}} token gated only by `{kws[0]}` appearing somewhere in the FILE — no proximity requirement, so one incidental occurrence licenses every token in the file"
    if tc:
        return "D", f"a bare [{tc[0]}]{{{tc[1]}}} token with no keyword and no literal — nothing ties it to credential material"
    return "D","no literal, no assignment binding and no token class this inventory can identify"

inv=[]
for r in rules:
    cls,why=classify(r); tc=token_class(r["Pattern"]); kws=r.get("Keywords") or []
    md=r.get("Metadata") or {}
    inv.append(dict(id=r["ID"], description=r["Description"], klass=cls, why=why,
        keywords=kws, dictionary_word=[k for k in kws if k.lower() in words],
        pattern=r["Pattern"], token_alphabet=(tc[0] if tc else None), token_len=(tc[1] if tc else None),
        literals=literals(r["Pattern"])[:3], secret_shape=md.get("secret_shape")=="true",
        require_context_keywords=r.get("require_context_keywords") or [],
        exclude_context_keywords=r.get("exclude_context_keywords") or [],
        min_entropy=md.get("min_entropy"), severity=r["Severity"],
        fire=fire.get(r["ID"],0), repos=repos.get(r["ID"],0)))
json.dump(inv, open("docs/design/secret-rule-inventory.json","w"), indent=1)
grand=sum(fire.values())
c=collections.Counter(x["klass"] for x in inv); f=collections.Counter()
for x in inv: f[x["klass"]]+=x["fire"]
print(f"rules: {len(inv)}   benchmark findings (all analyzers): {grand:,}\n")
print(f"{'class':<6}{'rules':>7}{'findings':>14}{'share of all':>14}")
for k in "ABCD": print(f"{k:<6}{c[k]:>7}{f[k]:>14,}{f[k]/grand*100:>13.2f}%")
sec=sum(f.values()); print(f"\nall SEC-* = {sec:,} = {sec/grand*100:.2f}% of every finding")
