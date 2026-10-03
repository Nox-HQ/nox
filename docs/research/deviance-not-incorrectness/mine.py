#!/usr/bin/env python3
"""Mine structural invariants within one rule family and list the exceptions.

An invariant is A -> C over rule features, where C is one feature or the OR of
two. It is reported only with its exceptions, and only as "inspect these":
nothing here decides that an exception is wrong.

Two counts for every invariant, because a design convention copied into fifty
rules from one template is one decision, not fifty:
  rules     each rule is a vote
  lineages  rules sharing a pattern skeleton (vendor names masked) are one
            vote; a lineage satisfies C when most of its members do
"""
import json, sys, itertools, collections

UNIVERSAL_NOISE = {'has_references', 'matcher=regex'}

# Q2: features that describe HOW a rule establishes a credential. Only these
# may be combined in a disjunction; "format_prefix OR severity=high" is true of
# almost everything and means nothing.
EVIDENCE = {'format_prefix', 'assignment_binding', 'post_match_validation', 'private_key_block'}
STRUCTURAL = EVIDENCE | {'bare_token', 'proximity_gate', 'vendor_bound', 'secret_shape', 'min_entropy',
                         'word_boundary', 'case_insensitive', 'quoted_value', 'keyword_in_pattern',
                         'capture_group', 'file_filter', 'url_credential', 'entropy_matcher'}

def mine(rows, min_conf=0.9, min_support=20, max_exc_frac=0.10):
    feats = sorted({f for r in rows for f in r['features']} - UNIVERSAL_NOISE)
    have = [set(r['features']) for r in rows]
    consequents = [(c,) for c in feats] + list(itertools.combinations(sorted(EVIDENCE & set(feats)), 2))
    antecedents = [()] + [(a,) for a in feats if a in STRUCTURAL]
    out = []
    for A in antecedents:
        idxA = [i for i in range(len(rows)) if all(a in have[i] for a in A)]
        if len(idxA) < min_support:
            continue
        for C in consequents:
            if set(C) & set(A):
                continue
            sat = [i for i in idxA if any(c in have[i] for c in C)]
            exc = [i for i in idxA if i not in set(sat)]
            if not exc or len(sat) < min_support:
                continue
            conf = len(sat) / len(idxA)
            if conf < min_conf or len(exc) / len(idxA) > max_exc_frac:
                continue
            # lineage-collapsed
            units = collections.defaultdict(list)
            for i in idxA:
                units[rows[i]['skeleton']].append(i)
            usat = sum(1 for m in units.values() if sum(any(c in have[i] for c in C) for i in m) * 2 > len(m))
            out.append(dict(antecedent=list(A), consequent=list(C), n=len(idxA), support=len(sat),
                            confidence=round(conf, 3), lineages=len(units), lineage_support=usat,
                            lineage_confidence=round(usat / len(units), 3),
                            exceptions=[rows[i]['id'] for i in exc]))
    return out

def prune(found):
    """Keep the most general statement of each exception set: a consequent
    pair is dropped when one of its features alone already gives the same
    exceptions, and an antecedent is dropped when the empty antecedent does."""
    by_exc = collections.defaultdict(list)
    for f in found:
        by_exc[tuple(sorted(f['exceptions']))].append(f)
    keep = []
    for exc, fs in by_exc.items():
        fs.sort(key=lambda f: (len(f['antecedent']), len(f['consequent']), -f['confidence']))
        keep.append(fs[0])
    keep.sort(key=lambda f: (-f['confidence'], f['antecedent'], f['consequent']))
    return keep

if __name__ == '__main__':
    src, family, dest = sys.argv[1:4]
    rows = [r for r in json.load(open(src)) if r['family'] == family]
    found = prune(mine(rows))
    json.dump(found, open(dest, 'w'), indent=1)
    exc = collections.Counter(e for f in found for e in f['exceptions'])
    print(f'{family}: {len(rows)} rules, {len({r["skeleton"] for r in rows})} lineages, '
          f'{len(found)} invariants, {len(exc)} distinct exception rules')
    for f in found:
        a = ' & '.join(f['antecedent']) or family
        c = ' OR '.join(f['consequent'])
        print(f"  {a:30} -> {c:44} {f['support']:4}/{f['n']:<4} {f['confidence']:.3f}  "
              f"lineages {f['lineage_support']}/{f['lineages']} {f['lineage_confidence']:.3f}  "
              f"exc={len(f['exceptions'])} {f['exceptions'][:6]}")
