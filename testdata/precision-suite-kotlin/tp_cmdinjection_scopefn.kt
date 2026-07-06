// Command injection through a Kotlin SCOPE-FUNCTION chain — a labeled FALSE
// NEGATIVE nox's flat line-recognizer does not catch. The untrusted value is read
// and immediately piped into a `.let { }` lambda whose receiver (`cmd`) is passed
// to Runtime.getRuntime().exec, with no intermediate `val` binding. This is a real
// CWE-78 bug a correct scanner would fire TAINT-002 on — it is kept in the corpus,
// not deleted, because removing a hard true positive to inflate recall would defeat
// the point of an honest measurement suite.
//
// Why nox misses it: taint is introduced from source CALLS assigned to a variable,
// and propagated through variable reads. Here the source result is never bound to a
// name — it flows straight into the `.let { cmd -> ... }` lambda, and the recognizer
// does not model a scope-function lambda's parameter as an alias of its receiver.
// The `cmd` inside the lambda is therefore never marked tainted, so the .exec sink
// does not fire. Closing this needs scope-function/lambda-receiver modeling — future
// work, not a curation trick. See testdata/precision-suite-kotlin/README.md.
package com.example

import javax.servlet.http.HttpServletRequest

class ScopeRunner {
    fun run(request: HttpServletRequest) {
        request.getParameter("cmd").let { cmd ->
            Runtime.getRuntime().exec(cmd) // nox-expect: TAINT-002
        }
    }
}
