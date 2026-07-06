<?php
// SSRF: a user-supplied URL is fetched via cURL with no host allowlist, so an
// attacker can make the server request internal endpoints. CWE-918, TAINT-006.

function proxy()
{
    $url = $_GET['url'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch); // nox-expect: TAINT-006
}
