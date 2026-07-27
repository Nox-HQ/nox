// Command injection laundered through a Groovy CLOSURE. `with { c -> }` is the
// same receiver-aliasing shape as Kotlin's `.let { }`: the closure parameter IS
// the value the closure was applied to, so the untrusted `cmd` reaches
// .execute(). CWE-78.
//
// The recognizer now emits that binding when it sees the closure header, so `c`
// is tainted inside the body and the sink fires. This was a documented false
// negative until the aliasing landed; it is kept as the regression test for it.
package com.example

class Runner {
    def go(request) {
        request.getParameter("cmd").with { c ->
            c.execute() // nox-expect: TAINT-002
        }
    }
}
