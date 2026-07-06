// Command injection: an attacker-controlled query parameter flows into a shell
// invocation via Process.Start("cmd.exe", "/c ...") with no allow-list — CWE-78.
// A correct scanner fires TAINT-002.
using System.Diagnostics;
using System.Web;

public class ReportController
{
    // RunReport shells out to a user-supplied report name — the vulnerability.
    public void RunReport(HttpRequest Request)
    {
        var name = Request.QueryString["report"];
        Process.Start("cmd.exe", "/c generate-report " + name); // nox-expect: TAINT-002
    }
}
