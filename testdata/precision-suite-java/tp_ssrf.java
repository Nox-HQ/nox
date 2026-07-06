// SSRF: a user-supplied URL is fetched server-side with no host allowlist, so
// an attacker can reach internal services (169.254.169.254, localhost admin
// ports) — CWE-918. A correct scanner fires TAINT-006.
package com.example.proxy;

import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class UrlProxy {

    // fetch opens a connection to an attacker-controlled URL — the vulnerability.
    public InputStream fetch(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        return new URL(target).openStream(); // nox-expect: TAINT-006
    }
}
