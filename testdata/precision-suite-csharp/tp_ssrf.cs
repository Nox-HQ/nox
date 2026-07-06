// Server-side request forgery: an attacker-controlled URL flows into
// WebClient.DownloadString with no host allow-list — CWE-918. A correct scanner
// fires TAINT-006. The server will fetch any URL the caller supplies, including
// internal metadata endpoints.
using System.Net;
using System.Web;

public class ProxyController
{
    // Fetch downloads whatever URL the caller passes — the vulnerability.
    public string Fetch(HttpRequest Request)
    {
        var target = Request.QueryString["url"];
        var client = new WebClient();
        return client.DownloadString(target); // nox-expect: TAINT-006
    }
}
