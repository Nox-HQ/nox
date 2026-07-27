// Command injection through a Kotlin SCOPE-FUNCTION chain. The untrusted value
// is read and piped straight into a `.let { }` lambda whose parameter is passed
// to Runtime.getRuntime().exec, with no intermediate `val` binding. CWE-78.
//
// A scope function's lambda parameter ALIASES its receiver: `cmd` here IS the
// value `.let` was applied to. On seeing the lambda header the recognizer now
// emits that binding (`cmd = request.getParameter(...)`), so statements in the
// body — which arrive on later lines — resolve `cmd` as tainted and the sink
// fires. This was a documented false negative until the aliasing landed; it is
// kept as the regression test for it.
package com.example

import javax.servlet.http.HttpServletRequest

class ScopeRunner {
    fun run(request: HttpServletRequest) {
        request.getParameter("cmd").let { cmd ->
            Runtime.getRuntime().exec(cmd) // nox-expect: TAINT-002
        }
    }
}
