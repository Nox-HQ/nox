// Reflected XSS: an untrusted query parameter is written un-encoded into the
// HTML response via Response.Write — CWE-79. A correct scanner fires TAINT-003.
// The value is reflected verbatim, so "<script>...</script>" executes in the
// victim's browser.
using System.Web;

public class GreetController
{
    // Greet echoes the caller's name straight into the page — the vulnerability.
    public void Greet(HttpRequest Request, HttpResponse Response)
    {
        var name = Request.QueryString["name"];
        Response.Write("<h1>Hello " + name + "</h1>"); // nox-expect: TAINT-003
    }
}
