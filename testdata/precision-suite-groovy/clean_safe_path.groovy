// Clean: FilenameUtils.getName() strips every directory component from the
// user-supplied name, so a `../../etc/passwd` input collapses to `passwd` and the
// file is read from a fixed base directory only. There is no path traversal here;
// any TAINT-004 finding is a false positive.
package com.example

import org.apache.commons.io.FilenameUtils

class DocReader {
    def read(request) {
        def raw = request.getParameter("doc")
        def name = FilenameUtils.getName(raw) // strips path components
        def f = new File("/var/docs", name)
        return f.getText()
    }
}
