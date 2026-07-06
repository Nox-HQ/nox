// Sanitized input in Java — each untrusted value is neutralized for the sink it
// reaches: numeric coercion for a command argument, OWASP/Commons HTML escaping
// for output, and Commons FilenameUtils to strip path components. Zero findings
// expected.
package com.example.safe;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.text.StringEscapeUtils;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SanitizedHandler {

    // numeric coercion: parseInt rejects any non-numeric metacharacters, so the
    // shell command carries only a validated integer.
    public void runJob(HttpServletRequest request) throws IOException {
        String raw = request.getParameter("jobId");
        String jobId = Integer.parseInt(raw) + "";
        Runtime.getRuntime().exec("run-job " + jobId);
    }

    // HTML escaping: the reflected value is entity-encoded, defusing XSS.
    public void render(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String raw = request.getParameter("msg");
        String msg = StringEscapeUtils.escapeHtml4(raw);
        response.getWriter().println("<div>" + msg + "</div>");
    }

    // path component stripping: getName drops any directory traversal segments.
    public File openUpload(HttpServletRequest request) {
        String raw = request.getParameter("file");
        String safe = FilenameUtils.getName(raw);
        return new File("/var/www/uploads/" + safe);
    }
}
