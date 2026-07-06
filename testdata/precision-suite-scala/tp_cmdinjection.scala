// Command injection: a Play request query parameter is interpolated into a shell
// command run via scala.sys.process — CWE-78. A correct scanner fires TAINT-002.
// The tainted value is spliced into the command string rather than passed as a
// discrete argument vector, which is the injectable form.
package controllers

import scala.sys.process._

class ReportController {
  // generate runs an external tool named partly by untrusted input — the bug.
  def generate(request: Request): Int = {
    val name = request.getQueryString("report")
    val cmd = "generate-report " + name
    Process(cmd).run().exitValue() // nox-expect: TAINT-002
  }

  // bang runs the command via the postfix `.!` process operator — the same sink
  // reached through the scala.sys.process DSL rather than a Process(...) call.
  def bang(request: Request): Int = {
    val host = request.getQueryString("host")
    s"ping -c 1 $host".! // nox-expect: TAINT-002
  }
}
