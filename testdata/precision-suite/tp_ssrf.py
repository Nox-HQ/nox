# SSRF: an attacker-controlled URL flows into requests.get with no allowlist.
# The taint engine has an SSRF vuln class (CWE-918) but no requests.get sink
# yet, so this is a recall-gap regression target: it flips to a TP when the
# sink lands.
import requests  # nox-expect: SLOP-001
def proxy(request):
    target = request.args.get("url")
    return requests.get(target)  # nox-expect: TAINT-006
