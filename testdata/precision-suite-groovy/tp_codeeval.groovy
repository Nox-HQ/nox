// Code injection: a user-controlled request parameter is evaluated as Groovy via
// Eval.me, which runs arbitrary code in the server JVM. An attacker supplies
// `Runtime.getRuntime().exec(...)` as the expression and achieves RCE. This is
// CWE-95. A correct scanner fires TAINT-005. nox sees `expr` tainted by
// request.getParameter reach the Eval.me sink with no sanitizer on the path.
package com.example

class Calculator {
    def evaluate(request) {
        def expr = request.getParameter("expr")
        return Eval.me(expr) // nox-expect: TAINT-005
    }
}
