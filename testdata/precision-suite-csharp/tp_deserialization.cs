// Unsafe deserialization: attacker-controlled bytes are fed to
// BinaryFormatter.Deserialize — CWE-502, a well-known .NET RCE vector. A correct
// scanner fires TAINT-005. BinaryFormatter reconstructs arbitrary object graphs
// and is unsafe on any untrusted input.
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web;

public class SessionController
{
    // Restore rehydrates a session blob taken straight from the request — the bug.
    public object Restore(HttpRequest Request)
    {
        var blob = Request.Form["state"];
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(ToStream(blob)); // nox-expect: TAINT-005
    }

    private static Stream ToStream(string s) => new MemoryStream(System.Convert.FromBase64String(s));
}
