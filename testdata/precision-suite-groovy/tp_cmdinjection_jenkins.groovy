// Command injection in a Jenkins pipeline: a user-controlled build parameter is
// interpolated into the `sh` step's command line, which Jenkins runs through a
// shell. An attacker sets `branch` to `main; rm -rf /` and the shell obeys. This
// is CWE-78. A correct scanner fires TAINT-002. nox sees `branch` tainted by
// request.getParameter reach the `sh` sink; the tainted GString is arg 0 of the
// step (the whole command line), so the sink-arg policy treats it as dangerous.
package com.example

class Deploy {
    def run(request) {
        def branch = request.getParameter("branch")
        sh("git checkout ${branch} && make deploy") // nox-expect: TAINT-002
    }
}
