"""Reachability step 1: of the advisories stopped at affected_version, how many
sit in packages that are installed only as development dependencies?

uv.lock: roots are workspace/editable/virtual packages; runtime edges are
`dependencies` and `optional-dependencies` (extras: treated as runtime, the
conservative choice); `dev-dependencies` groups are not followed.
pnpm-lock.yaml: roots are importers' dependencies + optionalDependencies;
devDependencies are not followed; snapshots give transitive edges.
A package outside the runtime closure is dev-only. Anything that cannot be
resolved is 'unknown', never dev-only."""
import json, os, re, sys, tomllib, collections, yaml

corpus, out = sys.argv[1], sys.argv[2]
norm = lambda n: re.sub(r'[-_.]+', '-', n).lower()

def uv_runtime(path):
    d = tomllib.load(open(path, 'rb'))
    pk = {}
    for p in d.get('package', []):
        pk.setdefault(norm(p['name']), []).append(p)
    roots = [p for ps in pk.values() for p in ps
             if any(k in p.get('source', {}) for k in ('editable', 'virtual', 'workspace'))]
    seen, stack = set(), list(roots)
    while stack:
        p = stack.pop()
        key = (norm(p['name']), p.get('version'))
        if key in seen: continue
        seen.add(key)
        edges = list(p.get('dependencies', []))
        for ex in (p.get('optional-dependencies') or {}).values(): edges += ex
        for e in edges:
            for q in pk.get(norm(e['name']), []):
                if e.get('version') in (None, q.get('version')):
                    stack.append(q)
    return {n for n, _ in seen}, set(pk)

def pnpm_runtime(path):
    d = yaml.safe_load(open(path))
    snaps = d.get('snapshots') or d.get('packages') or {}
    def name_of(k):
        k = k.lstrip('/')
        at = k.rfind('@')
        return (k[:at] if at > 0 else k)
    idx = collections.defaultdict(list)
    for k in snaps: idx[name_of(k)].append(k)
    seen, stack = set(), []
    for imp in (d.get('importers') or {}).values():
        for grp in ('dependencies', 'optionalDependencies'):
            for n, spec in (imp.get(grp) or {}).items():
                v = spec.get('version') if isinstance(spec, dict) else spec
                stack.append(f'{n}@{v}')
    while stack:
        k = stack.pop()
        if k in seen or k.startswith(('link:', 'file:')): continue
        seen.add(k)
        s = snaps.get(k) or snaps.get('/' + k) or {}
        for grp in ('dependencies', 'optionalDependencies'):
            for n, v in (s.get(grp) or {}).items():
                stack.append(f'{n}@{v}')
    return {name_of(k) for k in seen}, set(idx)

cache, res = {}, collections.Counter()
detail = collections.defaultdict(collections.Counter)
for repo in sorted(os.listdir(out)):
    for f in json.load(open(f'{out}/{repo}/findings.json'))['findings']:
        m = f.get('Metadata') or {}
        if not f['RuleID'].startswith('VULN') or m.get('applicability_reached') != 'affected_version':
            continue
        lf = f['Location']['FilePath']; base = os.path.basename(lf)
        path = os.path.join(corpus, repo, lf)
        if base not in ('uv.lock', 'pnpm-lock.yaml'):
            res[(base, 'not measured')] += 1; continue
        if path not in cache:
            try:
                cache[path] = (uv_runtime if base == 'uv.lock' else pnpm_runtime)(path)
            except Exception as e:
                cache[path] = None
        c = cache[path]
        pkg = m.get('package', '')
        key = norm(pkg) if base == 'uv.lock' else pkg
        if c is None or key not in c[1]:
            verdict = 'unknown'
        elif key in c[0]:
            verdict = 'runtime'
        else:
            verdict = 'dev-only'
        res[(base, verdict)] += 1
        detail[(repo, base, verdict)][pkg] += 1
for k, n in sorted(res.items()): print(f'{n:5}  {k[0]:16} {k[1]}')
print()
for k, c in sorted(detail.items()):
    if k[2] == 'dev-only': print(k, c.most_common(8))
