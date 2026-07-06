// SSRF: a user-controlled URL read from the environment is set as libcurl's
// CURLOPT_URL and fetched with no host allow-list, so an attacker can point the
// request at internal metadata endpoints (169.254.169.254) or intranet hosts.
// This is CWE-918. A correct scanner fires TAINT-006; the fix validates the host
// against an allow-list before the request.
#include <stdlib.h>
#include <curl/curl.h>

void fetch_avatar(CURL *handle) {
    char *url = getenv("AVATAR_URL");
    curl_easy_setopt(handle, CURLOPT_URL, url); // nox-expect: TAINT-006
    curl_easy_perform(handle);
}
