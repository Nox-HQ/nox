// Command injection: a user-controlled request parameter is spliced into a GString
// command line and run via the Groovy String.execute() extension — no argument
// vector, no allow-list. This is CWE-78. A correct scanner fires TAINT-002. nox's
// Groovy taint model sees `name` tainted by request.getParameter reach the
// .execute sink (matched on the method suffix); lexctx emits the ${name}
// interpolation hole as code, so the tainted value is visible at the sink.
package com.example

class ReportRunner {
    def generate(request) {
        def name = request.getParameter("report")
        "generate-report --name ${name}".execute() // nox-expect: TAINT-002
    }
}
