// Clean: placeholder / example credentials that a broad secret regex trips on but
// which are NOT real secrets — they are documentation defaults and env-var lookups,
// never a hardcoded live key. There is no taint source here and no dangerous sink,
// so a correct scanner emits nothing; any finding is a false positive.
package com.example

object Config {
    // Example values shown in the README — obvious placeholders, not live secrets.
    const val EXAMPLE_API_KEY = "your-api-key-here"
    const val EXAMPLE_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx"
    const val SAMPLE_PASSWORD = "changeme"

    // The real values come from the environment at runtime, never from source.
    val apiKey: String = System.getenv("API_KEY") ?: EXAMPLE_API_KEY
    val dbPassword: String = System.getenv("DB_PASSWORD") ?: ""
}
