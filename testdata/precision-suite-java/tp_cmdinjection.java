// Command injection: an attacker-controlled request parameter flows into a
// shell invocation via Runtime.getRuntime().exec(...) with no allowlist. This
// is CWE-78. A correct scanner fires TAINT-002.
package com.example.handler;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportHandler {

    // generateReport shells out to a user-supplied report name — the vulnerability.
    public void generateReport(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("report");
        Runtime.getRuntime().exec("generate-report " + name); // nox-expect: TAINT-002
    }
}
