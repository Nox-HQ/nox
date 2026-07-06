// Path traversal: a request parameter is used to build a filesystem path that
// is then read, with no canonicalization or allow-base check — CWE-22. A
// ../../etc/passwd value escapes the intended directory. A correct scanner
// fires TAINT-004.
package com.example.files;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class FileServlet {

    // serve opens a file named directly by untrusted input — the vulnerability.
    public File serve(HttpServletRequest request) {
        String path = request.getParameter("file");
        return new File("/var/www/uploads/" + path); // nox-expect: TAINT-004
    }
}
