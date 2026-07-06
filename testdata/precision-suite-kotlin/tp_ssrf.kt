// SSRF: a user-controlled request parameter becomes a URL that the server then
// fetches with URL(u).openStream(), so an attacker can point the request at
// internal metadata endpoints (169.254.169.254) or intranet hosts. This is
// CWE-918. A correct scanner fires TAINT-006. nox's Kotlin taint model sees `u`
// tainted by request.getParameter reach the .openStream sink; the URL constructor
// itself is deliberately not a sink (constructing a URL performs no request), so
// the finding lands on the fetch, not the construction.
package com.example

import java.net.URL
import javax.servlet.http.HttpServletRequest

class Fetcher {
    fun fetch(request: HttpServletRequest) {
        val u = request.getParameter("url")
        val stream = URL(u).openStream() // nox-expect: TAINT-006
        stream.close()
    }
}
