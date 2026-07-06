// Path traversal: an untrusted file name flows into File.ReadAllText with no
// canonicalization or allow-base check — CWE-22. A correct scanner fires
// TAINT-004. An attacker supplying "../../etc/passwd" escapes the intended dir.
using System.IO;
using System.Web;

public class DownloadController
{
    // Serve reads whatever file the caller names — the vulnerability.
    public string Serve(HttpRequest Request)
    {
        var file = Request.QueryString["file"];
        return File.ReadAllText("/srv/reports/" + file); // nox-expect: TAINT-004
    }
}
