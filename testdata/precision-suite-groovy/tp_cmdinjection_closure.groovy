// Command injection laundered through a Groovy CLOSURE — a labeled FALSE NEGATIVE.
// This is a genuine CWE-78 bug (the untrusted `cmd` reaches .execute()), but nox's
// Groovy model does NOT catch it, and it is kept in the corpus rather than deleted:
// inflating recall by removing a hard true positive would defeat an honest suite.
//
// The idiom is idiomatic Groovy: the untrusted value is piped straight into a
// closure via `with { ... }` and the closure's implicit `it` / captured binding is
// executed, with no intermediate top-level `def` binding the sink reads. nox
// introduces taint from source calls assigned to a variable and propagates it
// through variable reads; it does not model a closure parameter (`c` here, or the
// implicit `it`) as an alias of the value the closure is applied to, so `c` inside
// the closure is never marked tainted and the .execute sink does not fire. Closing
// it needs closure/receiver modeling — future work, not a curation trick.
package com.example

class Runner {
    def go(request) {
        request.getParameter("cmd").with { c ->
            c.execute() // nox-expect: TAINT-002
        }
    }
}
