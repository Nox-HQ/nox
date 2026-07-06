// Clean: the user-controlled value is reduced to its last path component with
// FilenameUtils.getName(input) before being opened, stripping any `../` traversal
// sequence, so the read is confined to the intended directory. getName is a pure
// sanitizer call (it does not itself open a file), so the sanitized value that
// reaches FileInputStream carries no path-traversal taint. A correct scanner emits
// nothing; any TAINT-004 finding here is a false positive.
package com.example

import java.io.FileInputStream
import org.apache.commons.io.FilenameUtils
import javax.servlet.http.HttpServletRequest

class Downloader {
    fun read(request: HttpServletRequest, baseDir: String) {
        val requested = request.getParameter("file")
        val safe = FilenameUtils.getName(requested)
        val stream = FileInputStream(baseDir + "/" + safe)
        stream.close()
    }
}
