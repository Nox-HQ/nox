// Path traversal: a user-controlled request parameter names a file that the server
// then opens with new FileInputStream(path), so an attacker supplies
// `../../etc/passwd` and reads arbitrary files. This is CWE-22. A correct scanner
// fires TAINT-004. nox sees `path` tainted by request.getParameter reach the
// FileInputStream constructor sink with no FilenameUtils.getName / canonicalization
// on the path. (A single sink is used so the flow is reported exactly once — the
// `new File(p).getText()` idiom would legitimately report the same flow at both the
// File constructor and the .getText read.)
package com.example

class DocReader {
    def read(request) {
        def path = request.getParameter("doc")
        return new FileInputStream(path) // nox-expect: TAINT-004
    }
}
