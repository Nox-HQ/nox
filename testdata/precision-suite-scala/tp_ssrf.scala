// SSRF: a request parameter is used as the URL of an outbound fetch via
// java.net.URL.openStream — CWE-918. A correct scanner fires TAINT-006. The
// destination is fully attacker-controlled and is neither validated against an
// allow-list nor restricted to a known host, so it can reach internal services.
package controllers

import java.net.URL

class ProxyController {
  // fetch opens a stream to a URL taken directly from untrusted input — the bug.
  def fetch(request: Request): String = {
    val target = request.getQueryString("url")
    val stream = new URL(target).openStream() // nox-expect: TAINT-006
    scala.io.Source.fromInputStream(stream).mkString
  }
}
