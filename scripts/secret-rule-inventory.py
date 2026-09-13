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

def entropy_floor(r):
    """The entropy threshold a rule actually runs at, per candidate kind.

    Lives in Metadata, which an earlier dump omitted entirely -- so SEC-161's
    5.0-bit assignment threshold and its hex kind at 3.5-with-context were
    invisible, and a rule with four constraints was filed as a bare token with
    a file-level keyword. Read it from the built rule or do not classify.
    """
    md=r.get("metadata") or {}
    out={}
    for k,v in md.items():
        if k=="entropy_threshold": out["default"]=v
        elif k.startswith("entropy_threshold_"): out[k[len("entropy_threshold_"):]]=v
        elif k=="min_entropy": out["min"]=v
    return out

def leading_alternation(p):
    """Vendor prefixes written as a leading alternation.

    AWS keys are `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`. Read as a
    literal run that gave "3T", and the assignment test then described the rule
    as binding a key NAMED 3T -- a sentence that explains nothing and is also
    false. A leading alternation is a set of prefixes; say so.
    """
    q=strip_flags(p).lstrip()
    m=re.match(r'^(?:\\b)?\(?\(\?:([^)]{2,120})\)', q)
    if not m: return None
    alts=[a for a in m.group(1).split("|") if a]
    if len(alts)<2: return None
    clean=[re.sub(r'\[[^\]]*\]','',a) for a in alts]
    if not all(len(c)>=2 for c in clean): return None
    return alts

def leading_prefix(p):
    """The vendor prefix a pattern requires before its variable part.

    literals() returns the longest literal RUN, which for `\bph[xsar]_[A-Za-z0-9]{32,}`
    is "ph" -- true but useless in a sentence meant to explain what identifies
    the credential. The prefix is everything before the quantified class,
    alternations included: `ph[xsar]_`.
    """
    q=strip_flags(p)
    m=re.match(r'^(?:\\b)?((?:[A-Za-z0-9_.:/-]|\[[^\]]{1,40}\])+?)(?=\[[^\]]+\]\{)', q)
    if not m: return None
    pref=m.group(1)
    return pref if len(re.sub(r'\[[^\]]*\]','',pref))>=2 else None

def classify(r):
    p=r["Pattern"]; kws=r.get("Keywords") or []
    rck=r.get("require_context_keywords") or []
    md=r.get("metadata") or {}
    floors=entropy_floor(r)
    kinds=md.get("candidate_kinds")

    if r["MatcherType"]=="entropy":
        detail=f"at {floors.get('default','?')} bits"
        if kinds: detail+=f" over {kinds} candidates"
        percontext=[k for k in md if k.startswith("require_context_")]
        if rck or percontext or md.get("require_context")=="true":
            return "B", (f"an entropy rule {detail}, reported only where a nearby line names "
                         f"a secret; the threshold is a floor and the CONTEXT is the evidence")
        return "D", (f"an entropy rule {detail} with no proximity requirement -- entropy alone "
                     f"cannot separate a credential from a long identifier, measured: a Go test "
                     f"identifier scored 4.118 where a real AWS key scored 3.684")

    lits=literals(p)
    _alts_early=leading_alternation(p)
    if _alts_early and not is_structural(p):
        shown=", ".join(f"`{a}`" for a in _alts_early[:5])
        return "A", (f"the pattern requires one of {len(_alts_early)} vendor-issued prefixes "
                     f"({shown}) before its variable part, so a match identifies the "
                     f"credential on its own")
    if is_structural(p):
        return "A", f"the pattern requires the structural literal `{lits[0] if lits else p[:20]}` -- a URL or ARN form that identifies itself without any keyword gate"
    if binds_assignment(p):
        return "B", f"the pattern binds the key name `{lits[0]}` to the value with an assignment, so the DESTINATION says the value is credential material"
    alts=leading_alternation(p)
    if alts:
        shown=", ".join(f"`{a}`" for a in alts[:5])
        return "A", (f"the pattern requires one of {len(alts)} vendor-issued prefixes "
                     f"({shown}) before its variable part, so a match identifies the "
                     f"credential on its own")
    pref=leading_prefix(p)
    if pref:
        return "A", (f"the pattern requires the prefix `{pref}` before its variable part -- "
                     f"a vendor-issued marker that identifies the credential on its own, "
                     f"independently of the keyword gate")
    if lits:
        return "A", f"the pattern requires the literal `{lits[0]}`, which is discriminative on its own and does not depend on the keyword gate"

    tc=token_class(p)
    shape = md.get("secret_shape")=="true"
    guards=[]
    if shape: guards.append("a secret-shape filter")
    if floors.get("min"): guards.append(f"a {floors['min']}-bit entropy floor")
    guardtext = (" It additionally requires " + " and ".join(guards) + ".") if guards else ""

    if tc and rck:
        return "C", (f"the pattern is a bare [{tc[0]}]{{{tc[1]}}} token carrying nothing of the "
                     f"vendor's own credential format; its discrimination is the word `{rck[0]}` "
                     f"appearing within 4 lines and 512 characters of the match.{guardtext}")
    if tc and kws:
        return "D", (f"the pattern is a bare [{tc[0]}]{{{tc[1]}}} token gated only by `{kws[0]}` "
                     f"appearing somewhere in the FILE -- no proximity requirement, so one "
                     f"incidental occurrence licenses every token in the file.{guardtext}")
    if tc:
        return "D", f"a bare [{tc[0]}]{{{tc[1]}}} token with no keyword and no literal -- nothing ties it to credential material"
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
        metadata=r.get("metadata") or {}, entropy_floors=entropy_floor(r),
        candidate_kinds=(r.get("metadata") or {}).get("candidate_kinds"),
        file_patterns=r.get("file_patterns") or [],
        encodes_vendor_format=bool(literals(r["Pattern"])),
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
