// Command injection: a user-controlled request parameter is concatenated into a
// shell command string and handed to Runtime.getRuntime().exec — no argument
// vector, no allow-list. This is CWE-78. A correct scanner fires TAINT-002.
// nox's Kotlin taint model sees `name` tainted by request.getParameter reach the
// .exec sink (matched on the method suffix) with no sanitizer on the path.
package com.example

import javax.servlet.http.HttpServletRequest

class ReportRunner {
    fun generate(request: HttpServletRequest) {
        val name = request.getParameter("report")
        val cmd = "generate-report --name " + name
        Runtime.getRuntime().exec(cmd) // nox-expect: TAINT-002
    }
}
