// Clean: the user-controlled value is coerced to an integer with String.toInt()
// before use, which throws on any non-numeric input and so strips every shell /
// SQL / path metacharacter. The value reaching exec is a validated Int rendered
// back to a string — no injection is possible. A correct scanner emits nothing;
// any TAINT-002 finding here is a false positive.
package com.example

import javax.servlet.http.HttpServletRequest

class JobRunner {
    fun run(request: HttpServletRequest) {
        val raw = request.getParameter("jobId")
        val jobId = raw.toInt()
        Runtime.getRuntime().exec("run-job --id " + jobId)
    }
}
