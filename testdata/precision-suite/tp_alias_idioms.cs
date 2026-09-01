// True positives for the C# `using X = Y;` alias.
//
// C# sinks are named by TYPE in the catalog (`Process.Start`), which is what
// code writes after a plain `using System.Diagnostics;`. A using-ALIAS renames
// the type and made the same call invisible.
//
// Known limit, deliberately not papered over: an alias that names a NAMESPACE
// (`using D = System.Diagnostics;` then `D.Process.Start`) resolves to neither
// the bare nor the fully-qualified form the catalog carries, and is still
// missed. Only the type-alias case below is claimed.
using Proc = System.Diagnostics.Process;

class AliasIdioms
{
    void AliasedStart(HttpRequest Request)
    {
        var user = Request.QueryString["cmd"];
        Proc.Start("sh", "-c " + user);  // nox-expect: TAINT-002
    }
}
