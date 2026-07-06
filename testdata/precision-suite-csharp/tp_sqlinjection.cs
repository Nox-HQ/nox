// SQL injection: a request parameter is string-concatenated into a SqlCommand's
// CommandText — CWE-89. A correct scanner fires TAINT-001. The tainted value is
// built into the query string rather than bound as a SqlParameter, which is the
// dangerous, injectable form; the resulting command is returned for execution.
using System.Data.SqlClient;
using System.Web;

public class UserRepository
{
    // BuildLookup composes the query by concatenating untrusted input — the bug.
    public SqlCommand BuildLookup(HttpRequest Request, SqlConnection conn)
    {
        var id = Request.QueryString["id"];
        return new SqlCommand("SELECT name, email FROM users WHERE id = '" + id + "'", conn); // nox-expect: TAINT-001
    }
}
