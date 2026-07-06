// Reflected XSS: an unescaped request parameter is written straight into the
// HTML response via the servlet response writer — CWE-79. A correct scanner
// fires TAINT-003. The escaped form lives in clean_safe_output.java.
package com.example.web;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GreetingServlet {

    // greet reflects untrusted input into the page unescaped — the vulnerability.
    public void greet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String msg = request.getParameter("msg");
        response.getWriter().println("<div>Hello, " + msg + "</div>"); // nox-expect: TAINT-003
    }
}
