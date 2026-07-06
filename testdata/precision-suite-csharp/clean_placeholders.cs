// Placeholder configuration and safe idioms — an appsettings-style stressor with
// obvious non-secret placeholder values and a constant-path file read. Nothing
// here is a live credential or an untrusted-input flow. Zero findings expected.
using System.IO;

public class Config
{
    // Placeholder connection settings — the values are literal placeholders a
    // developer replaces at deploy time, not real secrets.
    public const string ConnectionString = "Server=localhost;Database=app;User Id=REPLACE_ME;Password=CHANGE_ME;";
    public const string ApiKeyPlaceholder = "your-api-key-here";
    public const string ExampleToken = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

    // Reads a fixed, constant configuration file — no untrusted input reaches it.
    public static string LoadDefaults()
    {
        return File.ReadAllText("/etc/app/defaults.json");
    }
}
