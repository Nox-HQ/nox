// Path traversal: a user-controlled request parameter is used directly as a file
// path with no canonicalization or allow-base check, so `../../etc/passwd` reads
// outside the intended directory. This is CWE-22. A correct scanner fires
// TAINT-004. nox's Kotlin taint model sees `path` tainted by request.getParameter
// reach the FileInputStream(path) constructor sink with no File(...).name /
// normalize sanitizer on the path.
package com.example

import java.io.FileInputStream
import javax.servlet.http.HttpServletRequest

class Downloader {
    fun read(request: HttpServletRequest) {
        val path = request.getParameter("file")
        val stream = FileInputStream(path) // nox-expect: TAINT-004
        stream.close()
    }
}
