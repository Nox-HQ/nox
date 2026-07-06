// Reflected XSS: a user-controlled request parameter is written straight into the
// HTTP response body with no HTML-encoding, so an attacker's `<script>` payload is
// reflected to the victim's browser. This is CWE-79. A correct scanner fires
// TAINT-003. nox's Kotlin taint model sees `comment` tainted by request.getParameter
// reach the response writer .write sink with no escapeHtml4 / htmlEscape sanitizer
// on the path.
package com.example

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class CommentView {
    fun render(request: HttpServletRequest, response: HttpServletResponse) {
        val comment = request.getParameter("comment")
        val html = "<div class=\"comment\">" + comment + "</div>"
        val writer = response.getWriter()
        writer.write(html) // nox-expect: TAINT-003
    }
}
