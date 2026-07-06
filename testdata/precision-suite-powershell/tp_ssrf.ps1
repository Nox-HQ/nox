# SSRF: an untrusted URL is fetched with Invoke-WebRequest, letting an attacker
# point the request at internal metadata endpoints or intranet hosts. CWE-918. A
# correct scanner fires TAINT-006.
$target = $args[0]
$url = $target
Invoke-WebRequest -Uri $url -OutFile "out.dat"  # nox-expect: TAINT-006
