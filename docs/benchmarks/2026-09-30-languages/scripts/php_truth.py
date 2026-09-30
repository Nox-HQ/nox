"""Build a bentoo-sarif truth file from the NIST SARD PHP Vulnerability Test
Suite (2015-10-27). Each case directory NNNNNN-v1.0.0 holds a manifest.sarif
whose run properties carry state good/bad; the CWE is in the source file's
name (src/CWE_89_...). The input kind (from the description) is kept so the
score can be split by where the tainted value comes from.
usage: php_truth.py SUITE_DIR > php-truth.sarif"""
import json,os,re,sys
root=sys.argv[1]; res=[]
for d in sorted(os.listdir(root)):
    p=os.path.join(root,d,'manifest.sarif')
    if not os.path.exists(p): continue
    run=json.load(open(p))['runs'][0]
    uri=run['artifacts'][0]['location']['uri']
    cwe=re.match(r'src/CWE_(\d+)_',uri).group(1)
    desc=run['properties']['description']
    m=re.search(r'input : (.*)',desc)
    res.append({'kind':'fail' if run['properties']['state']=='bad' else 'pass','ruleId':'CWE-'+cwe,
                'properties':{'input':re.sub(r'\s+',' ',m.group(1) if m else '')[:60]},
                'locations':[{'physicalLocation':{'artifactLocation':{'uri':f'{d}/{uri}'}}}]})
json.dump({'runs':[{'results':res}]},sys.stdout)
