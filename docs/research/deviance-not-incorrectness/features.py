#!/usr/bin/env python3
"""Structural features of secret rules, read from a BUILT rule dump.

Every feature is a property of the rule definition as the engine runs it --
never of corpus behaviour. Families and genealogy are derived here too, so the
mining step sees one table.
"""
import json, re, sys, hashlib, collections

def strip_flags(p):
    return re.sub(r'^\(\?[a-zA-Z]+\)', '', p)

BIND = re.compile(r'\[=:\]|\[:=\]|\(\?:=\|>\|:\{1,3\}=[^)]*\)')
LEAD = re.compile(r'^(?:\\b|\\s\*|\\s\+|\[ \\t\]\*|\[ \\t\]\+|\(\?:\[-\\\[\]\\s\*\)\?|\["\']\??|\[\'"\]\??|\["\\x27\]\??|["\']\??|\(\?:|\(|\s)+')

def value_part(p):
    """The part of a pattern that describes the CREDENTIAL: after the last
    assignment binding, if there is one. A vendor name in the binding is
    evidence of where the value sits, not of what the value looks like."""
    q = strip_flags(p)
    parts = BIND.split(q)
    return parts[-1] if len(parts) > 1 else q

def literal_prefix(p):
    """A format the credential itself carries: the value part opens with a
    required literal of >= 2 characters (`ghp_`, `dp\\.st\\.`), or with an
    alternation whose every branch does (`AKIA|ASIA`), possibly with a small
    class inside (`ph[xsar]_`). Returns the first such literal, or ''."""
    v = LEAD.sub('', value_part(p))
    # alternation of literal-led branches: (?:AKIA|ASIA|A3T[A-Z0-9]) or (AKIA|...)
    m = re.match(r'^((?:[A-Za-z0-9_\-]|\\.){2,})', v)
    if m and re.search(r'[A-Za-z0-9]', m.group(1)):
        return m.group(1)
    m = re.match(r'^((?:[A-Za-z0-9_\-]|\\.)+)\[[^\]]{1,8}\]((?:[A-Za-z0-9_\-]|\\.)+)', v)
    if m and len(m.group(1)) + len(m.group(2)) >= 2:
        return m.group(0)
    # leading alternation group: every branch starts with >= 2 literal chars
    if v.startswith('(') or v.startswith('(?:'):
        depth, i = 0, 0
        start = 3 if v.startswith('(?:') else 1
        for i, c in enumerate(v):
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
        inner = v[start:i]
        branches = [b for b in re.split(r'\|(?![^(]*\))', inner) if b]
        if branches and all(re.match(r'^(?:\(\?:)?(?:[A-Za-z0-9_\-]|\\.){2,}', b) for b in branches):
            return inner
    return ''

def features(r):
    p = r['Pattern'] or ''
    q = strip_flags(p)
    md = r.get('Metadata') or {}
    shape = md.get('bound_shape') or ''
    f = {}
    f['matcher=' + (r['MatcherType'] or 'regex')] = True
    f['format_prefix'] = bool(literal_prefix(shape or p)) or bool(re.search(r'-----BEGIN', p))
    f['assignment_binding'] = bool(BIND.search(q)) or bool(re.search(r'=\s*\\?["\']|:\s*\\?["\']', q)) or bool(md.get('vendor_bound'))
    f['bare_token'] = bool(re.fullmatch(r'(?:\\b)?\[[^\]]+\]\{\d+(?:,\d*)?\}(?:\\b)?', q))
    f['proximity_gate'] = bool(r.get('RequireContextKeywords'))
    f['vendor_bound'] = md.get('vendor_bound') == 'true'
    f['secret_shape'] = md.get('secret_shape') == 'true'
    f['min_entropy'] = 'min_entropy' in md
    f['entropy_matcher'] = r['MatcherType'] == 'entropy'
    f['post_match_validation'] = bool(r.get('ValidateMatch'))
    f['word_boundary'] = '\\b' in p
    f['case_insensitive'] = p.startswith('(?i)') or '(?i' in p
    f['quoted_value'] = bool(re.search(r'\[\\?"\\?\'\]|\["\\x27\]|\[\'"\]|\["\'\]', p))
    kw = [k.lower() for k in (r.get('Keywords') or [])]
    pl = p.lower()
    f['keyword_in_pattern'] = any(k and re.escape(k).replace('\\', '') in pl for k in kw)
    f['file_filter'] = bool(r.get('FilePatterns'))
    f['severity=' + (r['Severity'] or '')] = True
    f['confidence=' + (r['Confidence'] or '')] = True
    f['remediation_generic'] = (r.get('Remediation') or '').strip() in (
        'Rotate the exposed credential immediately', 'Rotate the exposed credential immediately.')
    f['has_references'] = bool(r.get('References'))
    f['private_key_block'] = '-----BEGIN' in p or 'PRIVATE KEY' in p
    f['url_credential'] = '://' in p
    f['capture_group'] = bool(re.search(r'\((?!\?)', q))
    return {k: v for k, v in f.items() if v}

VENDOR_DESC = [
    re.compile(r'^Detected (?P<v>.+?) (?:API|Access|Secret|Client|Auth|Private|Webhook|Personal|App|Bot|Service|Management|Admin|Signing|Encryption|OAuth|Refresh|Session|Deploy|Publish|Integration|Account|Server|Master|Read|Write|Live|Test|Production|Sandbox|Project|Organization|Org|User|Team|Workspace|Install|Installation|Key|Token|Password|Credential|Secret)'),
    re.compile(r'^(?P<v>.+?) (?:API key|API Key|token|Token|key|Key|secret|Secret|credentials?|Credentials?)( detected| exposed)?$'),
]

def family(r, f):
    """Rule family from the definition: what KIND of credential claim it makes.
    Deliberately coarse; Q1 measures how often it is ambiguous."""
    d = r.get('Description') or ''
    dl = d.lower()
    if f.get('entropy_matcher') or 'entropy' in (r.get('Tags') or []):
        return 'entropy'
    if f.get('private_key_block'):
        return 'private_key'
    if f.get('url_credential') or 'connection string' in dl or 'database url' in dl:
        return 'url_credential'
    if 'generic' in dl or (r.get('Metadata') or {}).get('generic_fallback'):
        return 'generic'
    if 'jwt' in dl or 'json web token' in dl:
        return 'jwt'
    if 'password' in dl and not re.search(r'detected [a-z0-9]', dl):
        return 'password'
    return 'vendor'

def skeleton(r):
    """Pattern with every keyword literal masked: rules stamped from one
    template share a skeleton however the vendor is spelt."""
    md = r.get('Metadata') or {}
    p = md.get('bound_shape') or r['Pattern'] or ''
    s = p.lower()
    for k in sorted((r.get('Keywords') or []), key=len, reverse=True):
        if len(k) >= 3:
            s = s.replace(k.lower(), '<V>')
    return s

def desc_template(r):
    d = r.get('Description') or ''
    m = re.match(r'^Detected (.+?) (API Key|API Token|Access Token|Secret|Token|Key)$', d)
    if m:
        return 'Detected <V> ' + m.group(2)
    m = re.match(r'^(.+?) (API key|token|key|secret) detected$', d, re.I)
    if m:
        return '<V> ' + m.group(2).lower() + ' detected'
    return 'other:' + d

if __name__ == '__main__':
    src, dest = sys.argv[1:3]
    rows = []
    for r in json.load(open(src)):
        if not r['ID'].startswith('SEC-'):
            continue
        f = features(r)
        rows.append(dict(id=r['ID'], description=r.get('Description'), pattern=r['Pattern'],
                         bound_shape=(r.get('Metadata') or {}).get('bound_shape'),
                         keywords=r.get('Keywords'), family=family(r, f), features=sorted(f),
                         skeleton=skeleton(r), desc_template=desc_template(r),
                         remediation=r.get('Remediation')))
    json.dump(rows, open(dest, 'w'), indent=1)
    print(len(rows), collections.Counter(x['family'] for x in rows))
