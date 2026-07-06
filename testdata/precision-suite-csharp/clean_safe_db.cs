// Safe database, output, and path idioms in C# — every one is the correct,
// guarded form, so a precise scanner fires nothing. Zero findings expected.
using System.Data.SqlClient;
using System.IO;
using System.Web;

public class SafeRepository
{
    // Parameterized query: the untrusted id is bound via AddWithValue as a
    // SqlParameter, never concatenated into the CommandText — no injection.
    public void LookupUser(HttpRequest Request, SqlConnection conn)
    {
        var id = Request.QueryString["id"];
        var cmd = new SqlCommand("SELECT name FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteReader();
    }

    // Output encoding: the reflected value is HtmlEncode'd before Response.Write,
    // so any markup is neutralized — no XSS.
    public void Greet(HttpRequest Request, HttpResponse Response)
    {
        var name = Request.QueryString["name"];
        var safe = HttpUtility.HtmlEncode(name);
        Response.Write("<h1>Hello " + safe + "</h1>");
    }

    // Path safety: GetFileName strips directory components and int.Parse coerces
    // the page number to an integer, so neither can traverse the filesystem.
    public string ReadPage(HttpRequest Request)
    {
        var raw = Request.QueryString["file"];
        var name = Path.GetFileName(raw);
        var rawPage = Request.QueryString["page"];
        var page = int.Parse(rawPage);
        return File.ReadAllText("/srv/reports/" + name + "." + page);
    }
}
